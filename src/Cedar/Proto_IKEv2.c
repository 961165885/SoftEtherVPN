// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IKEv2.c
// IKEv2 (RFC 7296) responder implementation
//
// This module implements the responder side of the IKEv2 protocol on top of
// the IKE_SERVER infrastructure that is shared with the IKEv1
// implementation: the UDP listener and NAT-T decapsulation, the IKE_CLIENT
// endpoint management, the IPSECSA pair data path and the interrupt driven
// timers all come from Proto_IKE.c.
//
// Exchanges implemented in this phase:
//   - IKE_SA_INIT: proposal selection, DH, SKEYSEED / prf+ key derivation,
//     NAT detection notifies and retransmission handling
//   - IKE_AUTH: PSK authentication of the initiator, generation of the
//     responder AUTH payload and creation of the first Child SA
//   - INFORMATIONAL: DPD (empty request / response), DELETE of the IKE SA
//     and of Child SAs, silent ignoring of unknown notifies
//   - CREATE_CHILD_SA: rejected with NO_ADDITIONAL_SAS (rekey support is
//     a later phase)
//
// Message ID handling follows RFC 7296 section 2.2: a request whose Message
// ID equals the expected next ID is processed, a retransmission of the
// previous request (expected ID minus one) is answered by resending the
// cached response, everything else is silently discarded.

#include "Proto_IKEv2.h"

#include "Account.h"
#include "Cedar.h"
#include "Hub.h"
#include "IPC.h"
#include "Logging.h"
#include "Proto_IPsec.h"
#include "Proto_PPP.h"
#include "Server.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

// Compare the data of a NAT detection notify with a calculated hash
static bool IkeV2CompareNotifyData(IKE_PACKET_PAYLOAD *notify_payload, BUF *hash);

//// Utility

// Get the IKEv2 notification payload of the specified message type
IKE_PACKET_PAYLOAD *IkeV2GetNotifyPayload(IKE_PACKET *pr, UINT notify_type, UINT index)
{
	UINT i, num = 0;
	// Validate arguments
	if (pr == NULL || pr->PayloadList == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(pr->PayloadList); i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(pr->PayloadList, i);

		if (p->PayloadType == IKEV2_PAYLOAD_NOTIFY && p->Payload.Notice.MessageType == notify_type)
		{
			if (num == index)
			{
				return p;
			}
			num++;
		}
	}

	return NULL;
}

// Get the SHA-1 hash algorithm
IKE_HASH *IkeV2GetSha1(IKE_SERVER *ike)
{
	return GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA1);
}

// Mark an IKEv2 IKE SA for deletion without sending any notify
// (the IKEv1 delete notify format must not be sent to an IKEv2 peer)
void IkeV2MarkIkeSaDeleted(IKE_SERVER *ike, IKE_SA *sa)
{
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	if (sa->Deleting)
	{
		return;
	}

	ike->StateHasChanged = true;

	sa->Deleting = true;

	IPsecLog(ike, NULL, sa, NULL, "LI2_DELETE_IKE_SA");
}

// Mark a whole IKEv2 IKE_CLIENT (all its SAs) for deletion without any notify
void IkeV2MarkIkeClientDeleted(IKE_SERVER *ike, IKE_CLIENT *c)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	if (c->Deleting)
	{
		return;
	}

	ike->StateHasChanged = true;

	c->Deleting = true;

	for (i = 0; i < LIST_NUM(ike->IkeSaList); i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

		if (sa->IkeClient == c && sa->Deleting == false)
		{
			sa->Deleting = true;
		}
	}

	for (i = 0; i < LIST_NUM(ike->IPsecSaList); i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

		if (sa->IkeClient == c && sa->Deleting == false)
		{
			sa->Deleting = true;
		}
	}

	IPsecLog(ike, c, NULL, NULL, "LI2_DELETE_IKE_CLIENT");
}

//// Entry point

// Process a received IKEv2 packet
void ProcIkeV2PacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header)
{
	IKE_CLIENT *c;
	IKE_SA *sa;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL)
	{
		return;
	}

	if (header->MinorVersion != 0)
	{
		// Only IKEv2.0 is supported
		return;
	}

	if (header->FlagV2Response)
	{
		// We never initiate anything in this phase: responses are ignored
		return;
	}

	if (header->FlagV2Initiator == false)
	{
		// A request must always have the I flag set by the original initiator
		return;
	}

	if (header->InitiatorCookie == 0)
	{
		return;
	}

	c = SearchOrCreateNewIkeClientForIkePacket(ike, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort, header);

	if (c == NULL)
	{
		return;
	}

	switch (header->ExchangeType)
	{
	case IKE_EXCHANGE_TYPE_IKE_SA_INIT:
		IkeV2ProcSaInit(ike, p, header, c);
		break;

	case IKE_EXCHANGE_TYPE_IKE_AUTH:
	case IKE_EXCHANGE_TYPE_INFORMATIONAL:
	case IKE_EXCHANGE_TYPE_CREATE_CHILD_SA:
		if (header->ResponderCookie == 0)
		{
			return;
		}

		sa = FindIkeSaByResponderCookieAndClient(ike, header->ResponderCookie, c);

		if (sa == NULL || sa->MajorVersion != IKE_MAJOR_VERSION_2)
		{
			// Unknown SPI: silently discard (RFC 7296 section 2.21)
			return;
		}

		switch (header->ExchangeType)
		{
		case IKE_EXCHANGE_TYPE_IKE_AUTH:
			IkeV2ProcIkeAuth(ike, p, header, c, sa);
			break;

		case IKE_EXCHANGE_TYPE_INFORMATIONAL:
			IkeV2ProcInformational(ike, p, header, c, sa);
			break;

		case IKE_EXCHANGE_TYPE_CREATE_CHILD_SA:
			IkeV2ProcCreateChildSa(ike, p, header, c, sa);
			break;
		}
		break;

	default:
		// Unknown exchange type: silently discard
		break;
	}
}

//// IKE_SA_INIT

// Process an IKE_SA_INIT request
void IkeV2ProcSaInit(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c)
{
	IKE_SA *sa = NULL;
	IKE_PACKET *pr = NULL;
	IKE_PACKET_PAYLOAD *sa_payload = NULL, *ke_payload = NULL, *nonce_payload = NULL;
	IKE_SA_TRANSFORM_SETTING setting;
	USHORT invalid_ke_group = 0;
	USHORT ke_group = 0;
	UCHAR *ke_data = NULL;
	UINT ke_data_size = 0;
	DH_CTX *dh = NULL;
	UCHAR *shared = NULL;
	UINT shared_size = 0;
	LIST *payload_list;
	IKE_PACKET *ps;
	BUF *nat_src = NULL, *nat_dst = NULL;
	IKE_PACKET_PAYLOAD *tmp_payload;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL)
	{
		return;
	}

	// Retransmission handling: a repeated IKE_SA_INIT for an SA whose
	// response is still cached is answered by resending that response
	sa = FindIkeSaByEndPointAndInitiatorCookie(ike, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort,
		header->InitiatorCookie, IKE_MAJOR_VERSION_2, IKEV2_SA_MODE_NONE);

	if (sa != NULL)
	{
		if (sa->V2State == IKEV2_STATE_SA_INIT_SENT && sa->SendBuffer != NULL)
		{
			IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &c->ServerIP, c->ServerPort, &c->ClientIP, c->ClientPort,
				Clone(sa->SendBuffer->Buf, sa->SendBuffer->Size), sa->SendBuffer->Size);

			sa->LastCommTick = ike->Now;
		}

		// In any other state the packet is a stray duplicate: discard it
		return;
	}

	pr = IkeParse(p->Data, p->Size, NULL);

	if (pr == NULL)
	{
		return;
	}

	sa_payload = IkeGetPayload(pr->PayloadList, IKEV2_PAYLOAD_SA, 0);
	ke_payload = IkeGetPayload(pr->PayloadList, IKEV2_PAYLOAD_KEY_EXCHANGE, 0);
	nonce_payload = IkeGetPayload(pr->PayloadList, IKEV2_PAYLOAD_NONCE, 0);

	if (sa_payload == NULL || ke_payload == NULL || nonce_payload == NULL)
	{
		// Broken packet
		IPsecLog(ike, c, NULL, NULL, "LI2_INVALID_PACKET");

		goto cleanup;
	}

	// Select a proposal
	Zero(&setting, sizeof(setting));

	if (IkeV2SelectIkeSaProposal(ike, sa_payload, &setting, &invalid_ke_group) == false)
	{
		UCHAR group_be[2];

		IPsecLog(ike, c, NULL, NULL, "LI_IKE_NO_TRANSFORM");

		group_be[0] = (UCHAR)((invalid_ke_group >> 8) & 0xff);
		group_be[1] = (UCHAR)(invalid_ke_group & 0xff);

		IkeV2SendPlainNotifyResponse(ike, c, header,
			invalid_ke_group != 0 ? IKEV2_NOTIFY_INVALID_KE_PAYLOAD : IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
			invalid_ke_group != 0 ? group_be : NULL,
			invalid_ke_group != 0 ? sizeof(group_be) : 0);

		goto cleanup;
	}

	// Key exchange payload: DH group number (2 bytes), 2 reserved bytes,
	// then the public value (RFC 7296 section 3.4)
	{
		BUF *ke_body = ke_payload->Payload.GeneralData.Data;

		if (ke_body == NULL || ke_body->Size < 6)
		{
			goto cleanup;
		}

		ke_group = (USHORT)(((USHORT)((UCHAR *)ke_body->Buf)[0] << 8) | (USHORT)((UCHAR *)ke_body->Buf)[1]);
		ke_data = (UCHAR *)ke_body->Buf + 4;
		ke_data_size = ke_body->Size - 4;
	}

	if (ke_group != (USHORT)setting.DhId)
	{
		// The KE group differs from the group selected from the SA proposal:
		// answer with our preferred group (network order)
		UCHAR our_group_be[2];
		USHORT our_group = (USHORT)setting.DhId;

		IPsecLog(ike, c, NULL, NULL, "LI_IKE_NO_TRANSFORM");

		our_group_be[0] = (UCHAR)((our_group >> 8) & 0xff);
		our_group_be[1] = (UCHAR)(our_group & 0xff);

		IkeV2SendPlainNotifyResponse(ike, c, header, IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
			our_group_be, sizeof(our_group_be));

		goto cleanup;
	}

	// Nonce: 16 to 256 octets (RFC 7296 section 3.9)
	{
		BUF *nonce_body = nonce_payload->Payload.GeneralData.Data;

		if (nonce_body == NULL || nonce_body->Size < 16 || nonce_body->Size > 256)
		{
			goto cleanup;
		}
	}

	// SA number quota for the client
	if (GetNumberOfIkeSaOfIkeClient(ike, c) > IKE_QUOTA_MAX_SA_PER_CLIENT)
	{
		goto cleanup;
	}

	// DH computation
	dh = IkeDhNewCtx(setting.Dh);

	if (dh == NULL)
	{
		goto cleanup;
	}

	// Some implementations (strongSwan with OpenSSL) emit the KE data with
	// additional leading zero bytes: strip them so that the size matches
	// the group size expected by DhCompute
	while (ke_data_size > dh->Size && ke_data_size >= 1 && ke_data[0] == 0x00)
	{
		ke_data++;
		ke_data_size--;
	}

	if (ke_data_size > dh->Size)
	{
		goto cleanup;
	}

	shared_size = dh->Size;
	shared = ZeroMalloc(shared_size);

	if (DhCompute(dh, shared, ke_data, ke_data_size) == false)
	{
		IPsecLog(ike, c, NULL, NULL, "LI_QM_DH_ERROR");

		goto cleanup;
	}

	// Create the IKE SA
	sa = NewIkeSa(ike, c, header->InitiatorCookie, IKEV2_SA_MODE_NONE, &setting);

	if (sa == NULL)
	{
		goto cleanup;
	}

	sa->MajorVersion = IKE_MAJOR_VERSION_2;

	Insert(ike->IkeSaList, sa);

	// Store the nonces and the shared DH secret
	sa->InitiatorRand = CloneBuf(nonce_payload->Payload.GeneralData.Data);
	sa->ResponderRand = RandBuf(IKEV2_NONCE_SIZE);
	sa->DhSharedKey = MemToBuf(shared, shared_size);

	// Derive the key material: SKEYSEED and the seven SK_* keys
	if (IkeV2CalcKeymat(ike, sa, shared, shared_size) == false)
	{
		IkeV2MarkIkeSaDeleted(ike, sa);
		goto cleanup;
	}

	// NAT detection
	IkeV2CheckNatD(ike, pr, p, header, sa);

	// Remember whether the peer announced RFC 7427 digital signature support
	sa->V2SignatureHashNotified = (IkeV2GetNotifyPayload(pr, IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS, 0) != NULL) ? true : false;

	// Save the raw IKE_SA_INIT request bytes: they feed the AUTH calculation
	sa->V2SaInitRequestData = MemToBuf(p->Data, p->Size);

	// Build the response: SA, KE, Nr, N(NAT_DETECTION_SOURCE_IP), N(NAT_DETECTION_DESTINATION_IP)
	payload_list = NewListFast(NULL);

	tmp_payload = IkeV2BuildIkeSaResponseProposal(ike, &setting);
	Add(payload_list, tmp_payload);

	// KE payload: our DH group number followed by our public key,
	// zero-padded on the left to the exact size of the DH group
	// (RFC 7296 section 3.4)
	{
		BUF *ke_buf = NewBuf();
		UCHAR group_be[2];
		UINT pad_size = (dh->MyPublicKey->Size < dh->Size) ? (dh->Size - dh->MyPublicKey->Size) : 0;
		UCHAR *pad = pad_size >= 1 ? ZeroMalloc(pad_size) : NULL;

		group_be[0] = (UCHAR)(ke_group >> 8);
		group_be[1] = (UCHAR)(ke_group);

		WriteBuf(ke_buf, group_be, sizeof(group_be));

		{
			// 2 reserved bytes after the DH group number
			UCHAR reserved2[2];
			Zero(reserved2, sizeof(reserved2));
			WriteBuf(ke_buf, reserved2, sizeof(reserved2));
		}

		if (pad != NULL)
		{
			WriteBuf(ke_buf, pad, pad_size);
			Free(pad);
		}

		WriteBuf(ke_buf, dh->MyPublicKey->Buf, dh->MyPublicKey->Size);

		Add(payload_list, IkeNewDataPayload(IKEV2_PAYLOAD_KEY_EXCHANGE, ke_buf->Buf, ke_buf->Size));

		FreeBuf(ke_buf);
	}

	Add(payload_list, IkeNewDataPayload(IKEV2_PAYLOAD_NONCE, sa->ResponderRand->Buf, sa->ResponderRand->Size));

	// NAT detection notifies: hashes of both endpoints as seen by us.
	// From this point on the responder SPI is known and used by both sides.
	{
		IKE_HASH *sha1 = IkeV2GetSha1(ike);

		nat_src = IkeCalcNatDetectHash(ike, sha1, sa->InitiatorCookie, sa->ResponderCookie,
			&c->ServerIP, c->ServerPort);
		nat_dst = IkeCalcNatDetectHash(ike, sha1, sa->InitiatorCookie, sa->ResponderCookie,
			&c->ClientIP, c->ClientPort);

		Add(payload_list, IkeV2NewNotifyPayload(0, IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
			NULL, 0, nat_src->Buf, nat_src->Size));
		Add(payload_list, IkeV2NewNotifyPayload(0, IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
			NULL, 0, nat_dst->Buf, nat_dst->Size));
	}

	// Announce the digital signature hash algorithms (RFC 7427) when the
	// server has a certificate: this tells signature-capable peers that the
	// responder can authenticate with RSA/SHA-256
	{
		bool has_cert = false;

		Lock(ike->Cedar->lock);
		{
			has_cert = (ike->Cedar->ServerX != NULL && ike->Cedar->ServerK != NULL);
		}
		Unlock(ike->Cedar->lock);

		if (has_cert)
		{
			// Hash algorithm registry value 2 = SHA-256 (RFC 7427 section 14.2)
			USHORT sha256_id = 2;
			UCHAR data_be[2];

			data_be[0] = (UCHAR)((sha256_id >> 8) & 0xff);
			data_be[1] = (UCHAR)(sha256_id & 0xff);

			Add(payload_list, IkeV2NewNotifyPayload(0, IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS,
				NULL, 0, data_be, sizeof(data_be)));
		}
	}

	ps = IkeV2New(sa->InitiatorCookie, sa->ResponderCookie, IKE_EXCHANGE_TYPE_IKE_SA_INIT,
		header->MessageId, false, true, payload_list);

	if (ps == NULL)
	{
		IkeFreePayloadList(payload_list);
		IkeV2MarkIkeSaDeleted(ike, sa);
		goto cleanup;
	}

	// Build, cache and send the response.
	// The raw response bytes feed our own AUTH calculation and the cache in
	// sa->SendBuffer serves the retransmission handling.
	{
		BUF *built = IkeBuild(ps, NULL);

		if (built == NULL)
		{
			IkeFree(ps);
			IkeV2MarkIkeSaDeleted(ike, sa);
			goto cleanup;
		}

		sa->V2SaInitResponseData = CloneBuf(built);

		if (sa->SendBuffer != NULL)
		{
			FreeBuf(sa->SendBuffer);
		}
		sa->SendBuffer = CloneBuf(built);
		sa->NextSendTick = ike->Now + (UINT64)IKE_SA_RESEND_INTERVAL;
		AddInterrupt(ike->Interrupts, sa->NextSendTick);

		// IkeSendUdpPacket hands the ownership of the data buffer to the
		// UDP packet: pass a clone
		IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &c->ServerIP, c->ServerPort, &c->ClientIP, c->ClientPort,
			Clone(built->Buf, built->Size), built->Size);

		FreeBuf(built);
	}

	IkeFree(ps);

	// State transition: wait for IKE_AUTH (Message ID 1)
	sa->V2State = IKEV2_STATE_SA_INIT_SENT;
	sa->V2MsgIdRecvExpected = 1;
	sa->V2MsgIdSendNext = 1;
	sa->LastCommTick = ike->Now;

	// Make this the client's current SA so that the long (non half-open)
	// timeout applies while the peer completes the IKE_AUTH exchange
	c->CurrentIkeSa = sa;

	IPsecLog(ike, c, sa, NULL, "LI2_IKE_SA_INIT_SENT",
		sa->InitiatorCookie, sa->ResponderCookie,
		setting.Dh->Name, setting.Crypto->Name, setting.CryptoKeySize * 8,
		setting.Hash->Name, setting.V2Prf->Name,
		sa->V2NatDetected ? _UU("L_YES") : _UU("L_NO"));

cleanup:
	if (pr != NULL)
	{
		IkeFree(pr);
	}

	if (dh != NULL)
	{
		DhFree(dh);
	}

	if (shared != NULL)
	{
		Free(shared);
	}

	FreeBuf(nat_src);
	FreeBuf(nat_dst);
}

//// Key derivation

// Derive SKEYSEED and the seven SK_* keys (RFC 7296 section 2.14)
bool IkeV2CalcKeymat(IKE_SERVER *ike, IKE_SA *sa, void *g_ir, UINT g_ir_size)
{
	IKE_HASH *prf;
	UINT prf_key_size, enc_key_size, integ_key_size;
	UINT total, offset = 0;
	UCHAR skeyseed[IKE_MAX_HASH_SIZE];
	UCHAR keymat[IKE_MAX_HASH_SIZE * 2 + IKE_MAX_KEY_SIZE * 2 + IKE_MAX_HASH_SIZE * 2];
	BUF *seed;
	// Validate arguments
	if (ike == NULL || sa == NULL || g_ir == NULL || g_ir_size == 0)
	{
		return false;
	}

	prf = sa->TransformSetting.V2Prf;

	if (prf == NULL || sa->TransformSetting.Crypto == NULL || sa->TransformSetting.Hash == NULL)
	{
		return false;
	}

	prf_key_size = prf->HashSize;
	enc_key_size = sa->TransformSetting.CryptoKeySize;
	integ_key_size = sa->TransformSetting.Hash->HashSize;

	total = prf_key_size +			// SK_d
		integ_key_size * 2 +			// SK_ai, SK_ar
		enc_key_size * 2 +			// SK_ei, SK_er
		prf_key_size * 2;				// SK_pi, SK_pr

	if (total > sizeof(keymat))
	{
		return false;
	}

	// SKEYSEED = prf(Ni | Nr, g^ir)
	seed = NewBuf();
	WriteBufBuf(seed, sa->InitiatorRand);
	WriteBufBuf(seed, sa->ResponderRand);

	IkeHMac(prf, skeyseed, seed->Buf, seed->Size, g_ir, g_ir_size);

	// KEYMAT = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
	FreeBuf(seed);

	seed = NewBuf();
	WriteBufBuf(seed, sa->InitiatorRand);
	WriteBufBuf(seed, sa->ResponderRand);
	WriteBufInt64(seed, sa->InitiatorCookie);
	WriteBufInt64(seed, sa->ResponderCookie);

	IkeCalcPrfPlus(prf, skeyseed, prf_key_size, seed->Buf, seed->Size, keymat, total);

	// Split the key material in order:
	// SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
	Copy(sa->V2SkD, keymat + offset, prf_key_size);
	offset += prf_key_size;

	Copy(sa->V2SkAi, keymat + offset, integ_key_size);
	offset += integ_key_size;

	Copy(sa->V2SkAr, keymat + offset, integ_key_size);
	offset += integ_key_size;

	Copy(sa->V2SkEi, keymat + offset, enc_key_size);
	offset += enc_key_size;

	Copy(sa->V2SkEr, keymat + offset, enc_key_size);
	offset += enc_key_size;

	Copy(sa->V2SkPi, keymat + offset, prf_key_size);
	offset += prf_key_size;

	Copy(sa->V2SkPr, keymat + offset, prf_key_size);

	// Create the encryption keys for both directions
	if (sa->V2KeyEi != NULL)
	{
		IkeFreeKey(sa->V2KeyEi);
	}
	sa->V2KeyEi = IkeNewKey(sa->TransformSetting.Crypto, sa->V2SkEi, enc_key_size);

	if (sa->V2KeyEr != NULL)
	{
		IkeFreeKey(sa->V2KeyEr);
	}
	sa->V2KeyEr = IkeNewKey(sa->TransformSetting.Crypto, sa->V2SkEr, enc_key_size);

	// Wipe the temporary secrets
	Zero(skeyseed, sizeof(skeyseed));
	Zero(keymat, sizeof(keymat));

	FreeBuf(seed);

	if (sa->V2KeyEi == NULL || sa->V2KeyEr == NULL)
	{
		return false;
	}

	return true;
}

// Derive the Child SA key material with explicit nonces:
// prf+ (SK_d, Ni | Nr). The initial Child SA uses the IKE_SA_INIT nonces,
// a rekey uses the nonces of the CREATE_CHILD_SA exchange.
BUF *IkeV2CalcChildSaKeymatEx(IKE_SERVER *ike, IKE_SA *sa, BUF *initiator_rand, BUF *responder_rand, UINT keymat_size)
{
	IKE_HASH *prf;
	BUF *seed, *ret;
	// Validate arguments
	if (ike == NULL || sa == NULL || initiator_rand == NULL || responder_rand == NULL || keymat_size == 0)
	{
		return NULL;
	}

	prf = sa->TransformSetting.V2Prf;

	if (prf == NULL)
	{
		return NULL;
	}

	seed = NewBuf();
	WriteBufBuf(seed, initiator_rand);
	WriteBufBuf(seed, responder_rand);

	ret = IkeCalcPrfPlusBuf(prf, sa->V2SkD, prf->HashSize, seed->Buf, seed->Size, keymat_size);

	FreeBuf(seed);

	return ret;
}

// Derive the Child SA key material: prf+ (SK_d, Ni | Nr) (RFC 7296 section 2.17)
BUF *IkeV2CalcChildSaKeymat(IKE_SERVER *ike, IKE_SA *sa, UINT keymat_size)
{
	return IkeV2CalcChildSaKeymatEx(ike, sa, sa->InitiatorRand, sa->ResponderRand, keymat_size);
}

//// Authentication (RFC 7296 section 2.15)

// Build the signed octets: RealMessage | Nonce | prf(SK_p, ID')
BUF *IkeV2CalcSignedOctets(IKE_SA *sa, BUF *real_message, BUF *nonce, void *skp, UINT skp_size, BUF *id_body)
{
	IKE_HASH *prf;
	UCHAR id_prf[IKE_MAX_HASH_SIZE];
	BUF *b;
	// Validate arguments
	if (sa == NULL || real_message == NULL || nonce == NULL || id_body == NULL)
	{
		return NULL;
	}

	prf = sa->TransformSetting.V2Prf;

	if (prf == NULL)
	{
		return NULL;
	}

	// prf(SK_p, ID'): the ID payload body including its own 4 byte header
	// but excluding the generic payload header
	IkeHMac(prf, id_prf, skp, skp_size, id_body->Buf, id_body->Size);

	b = NewBuf();
	WriteBufBuf(b, real_message);
	WriteBufBuf(b, nonce);
	WriteBuf(b, id_prf, prf->HashSize);

	return b;
}

// Verify the AUTH payload of the initiator (shared key / MSK method)
bool IkeV2VerifyInitiatorAuthSecret(IKE_SERVER *ike, IKE_SA *sa, IKE_PACKET_PAYLOAD *auth_payload,
									void *secret, UINT secret_size)
{
	bool ret = false;
	IKE_HASH *prf;
	UCHAR psk_key[IKE_MAX_HASH_SIZE];
	UCHAR calc[IKE_MAX_HASH_SIZE];
	UINT prf_key_size;
	BUF *octets = NULL;
	IKEV2_PACKET_AUTH_PAYLOAD *auth;
	// Validate arguments
	if (ike == NULL || sa == NULL || auth_payload == NULL || secret == NULL || secret_size == 0)
	{
		return false;
	}

	if (auth_payload->PayloadType != IKEV2_PAYLOAD_AUTH)
	{
		return false;
	}

	auth = &auth_payload->Payload.AuthV2;

	// Only the shared key message integrity code method is supported in this phase
	if (auth->Method != IKEV2_AUTH_METHOD_PSK)
	{
		return false;
	}

	prf = sa->TransformSetting.V2Prf;
	prf_key_size = prf->HashSize;

	if (auth->AuthData == NULL || auth->AuthData->Size != prf_key_size)
	{
		return false;
	}

	// psk_key = prf(secret, "Key Pad for IKEv2")
	IkeHMac(prf, psk_key, secret, secret_size,
		IKEV2_KEY_PAD_STRING, StrLen(IKEV2_KEY_PAD_STRING));

	// Signed octets of the initiator: the whole IKE_SA_INIT request,
	// our nonce Nr, and prf(SK_pi, IDi')
	octets = IkeV2CalcSignedOctets(sa, sa->V2SaInitRequestData, sa->ResponderRand,
		sa->V2SkPi, prf_key_size, sa->V2IdiBody);

	if (octets == NULL)
	{
		return false;
	}

	// AUTH = prf(psk_key, octets)
	IkeHMac(prf, calc, psk_key, prf_key_size, octets->Buf, octets->Size);

	ret = (Cmp(calc, auth->AuthData->Buf, prf_key_size) == 0) ? true : false;

	FreeBuf(octets);

	return ret;
}

// Build our own AUTH payload with an arbitrary secret (PSK or EAP MSK)
IKE_PACKET_PAYLOAD *IkeV2BuildAuthSecret(IKE_SERVER *ike, IKE_SA *sa, void *secret, UINT secret_size,
										 BUF *real_message, BUF *nonce, void *skp, UINT skp_size, BUF *id_body)
{
	IKE_HASH *prf;
	UCHAR psk_key[IKE_MAX_HASH_SIZE];
	UCHAR calc[IKE_MAX_HASH_SIZE];
	UINT prf_key_size;
	BUF *octets;
	IKE_PACKET_PAYLOAD *ret = NULL;
	// Validate arguments
	if (ike == NULL || sa == NULL || secret == NULL || secret_size == 0 ||
		real_message == NULL || nonce == NULL || id_body == NULL)
	{
		return NULL;
	}

	prf = sa->TransformSetting.V2Prf;
	prf_key_size = prf->HashSize;

	// psk_key = prf(secret, "Key Pad for IKEv2")
	IkeHMac(prf, psk_key, secret, secret_size,
		IKEV2_KEY_PAD_STRING, StrLen(IKEV2_KEY_PAD_STRING));

	// Signed octets of the responder: the whole IKE_SA_INIT response,
	// the nonce of the initiator Ni, and prf(SK_pr, IDr')
	octets = IkeV2CalcSignedOctets(sa, real_message, nonce, skp, skp_size, id_body);

	if (octets == NULL)
	{
		return NULL;
	}

	// AUTH = prf(psk_key, octets)
	IkeHMac(prf, calc, psk_key, prf_key_size, octets->Buf, octets->Size);

	ret = IkeV2NewAuthPayload(IKEV2_AUTH_METHOD_PSK, calc, prf_key_size);

	FreeBuf(octets);

	return ret;
}

//// Proposal selection

// Map an IKEv2 PRF transform ID to the corresponding hash algorithm
static IKE_HASH *IkeV2PrfIdToHash(IKE_SERVER *ike, UINT prf_id)
{
	switch (prf_id)
	{
	case IKEV2_PRF_HMAC_MD5:
		return GetIkeHash(ike->Engine, false, IKE_P1_HASH_MD5);

	case IKEV2_PRF_HMAC_SHA1:
		return GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA1);

	case IKEV2_PRF_HMAC_SHA2_256:
		return GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA2_256);
	}

	return NULL;
}

// Map an IKEv2 integrity transform ID to the hash algorithm and its ICV size
static IKE_HASH *IkeV2IntegIdToHash(IKE_SERVER *ike, UINT integ_id, UINT *icv_size)
{
	IKE_HASH *h = NULL;
	UINT size = 0;

	switch (integ_id)
	{
	case IKEV2_AUTH_HMAC_MD5_96:
		h = GetIkeHash(ike->Engine, false, IKE_P1_HASH_MD5);
		size = 12;
		break;

	case IKEV2_AUTH_HMAC_SHA1_96:
		h = GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA1);
		size = 12;
		break;

	case IKEV2_AUTH_HMAC_SHA2_256_128:
		h = GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA2_256);
		size = 16;
		break;
	}

	if (icv_size != NULL)
	{
		*icv_size = size;
	}

	return h;
}

// Select an IKE SA proposal (RFC 7296 section 3.10.1: the responder selects
// by its own preference among the acceptable proposals of the initiator)
bool IkeV2SelectIkeSaProposal(IKE_SERVER *ike, IKE_PACKET_PAYLOAD *sa_payload,
							  IKE_SA_TRANSFORM_SETTING *setting, USHORT *invalid_ke_group)
{
	IKEV2_PACKET_SA_PAYLOAD *sa;
	UINT i, j;
	bool dh_unsupported_only = false;
	// Validate arguments
	if (ike == NULL || sa_payload == NULL || setting == NULL || invalid_ke_group == NULL)
	{
		return false;
	}

	*invalid_ke_group = 0;

	if (sa_payload->PayloadType != IKEV2_PAYLOAD_SA)
	{
		return false;
	}

	sa = &sa_payload->Payload.SaV2;

	for (i = 0; i < LIST_NUM(sa->ProposalList); i++)
	{
		IKEV2_PROPOSAL *proposal = LIST_DATA(sa->ProposalList, i);

		if (proposal->ProtocolId != IKE_PROTOCOL_ID_IKE)
		{
			continue;
		}

		// Scan the transforms and pick the best supported algorithm of each
		// type using our own preference order
		IKE_CRYPTO *crypto = NULL;
		UINT crypto_id = 0, crypto_key_size = 0;
		IKE_HASH *prf = NULL;
		UINT prf_pref = 0, prf_id = 0;
		IKE_HASH *integ = NULL;
		UINT integ_pref = 0, integ_id = 0, integ_icv_size = 0;
		IKE_DH *dh_alg = NULL;
		UINT dh_pref = 0, dh_id = 0;

		for (j = 0; j < LIST_NUM(proposal->TransformList); j++)
		{
			IKEV2_TRANSFORM *t = LIST_DATA(proposal->TransformList, j);

			switch (t->TransformType)
			{
			case IKEV2_TRANSFORM_TYPE_ENCR:
				if (t->TransformId == IKEV2_ENCR_AES_CBC)
				{
					// Preference 1: AES-CBC. Without an explicit key length
					// attribute the default key length is 128 bits
					UINT key_bits = IkeV2GetKeyLengthBit(proposal);

					if (key_bits == 0)
					{
						key_bits = 128;
					}

					if (key_bits == 128 || key_bits == 192 || key_bits == 256)
					{
						if (crypto == NULL)
						{
							crypto = GetIkeCrypto(ike->Engine, false, IKE_P1_CRYPTO_AES_CBC);
							crypto_id = IKEV2_ENCR_AES_CBC;
							crypto_key_size = key_bits / 8;
						}
					}
				}
				else if (t->TransformId == IKEV2_ENCR_3DES)
				{
					// Preference 2: 3DES-CBC (compatibility)
					if (crypto == NULL)
					{
						crypto = GetIkeCrypto(ike->Engine, false, IKE_P1_CRYPTO_3DES_CBC);
						crypto_id = IKEV2_ENCR_3DES;
						crypto_key_size = 24;
					}
				}
				break;

			case IKEV2_TRANSFORM_TYPE_PRF:
				// Preference: SHA2-256 (1) > SHA1 (2) > MD5 (3)
				{
					UINT pref = 0;
					switch (t->TransformId)
					{
					case IKEV2_PRF_HMAC_MD5:		pref = 3; break;
					case IKEV2_PRF_HMAC_SHA1:		pref = 2; break;
					case IKEV2_PRF_HMAC_SHA2_256:	pref = 1; break;
					default:						pref = 0; break;
					}

					if (pref != 0 && (prf_pref == 0 || pref < prf_pref))
					{
						IKE_HASH *h = IkeV2PrfIdToHash(ike, t->TransformId);
						if (h != NULL)
						{
							prf = h;
							prf_pref = pref;
							prf_id = t->TransformId;
						}
					}
				}
				break;

			case IKEV2_TRANSFORM_TYPE_INTEG:
				// Preference: SHA2-256-128 (1) > SHA1-96 (2) > MD5-96 (3)
				{
					UINT pref = 0;
					switch (t->TransformId)
					{
					case IKEV2_AUTH_HMAC_MD5_96:		pref = 3; break;
					case IKEV2_AUTH_HMAC_SHA1_96:		pref = 2; break;
					case IKEV2_AUTH_HMAC_SHA2_256_128:	pref = 1; break;
					default:							pref = 0; break;
					}

					if (pref != 0 && (integ_pref == 0 || pref < integ_pref))
					{
						UINT icv = 0;
						IKE_HASH *h = IkeV2IntegIdToHash(ike, t->TransformId, &icv);
						if (h != NULL)
						{
							integ = h;
							integ_pref = pref;
							integ_id = t->TransformId;
							integ_icv_size = icv;
						}
					}
				}
				break;

			case IKEV2_TRANSFORM_TYPE_DH:
				// Preference: modp2048 (1) > modp4096 (2) > modp3072 (3) > modp1536 (4) > modp1024 (5)
				{
					UINT pref = 0;
					switch (t->TransformId)
					{
					case 2:		pref = 5; break;
					case 5:		pref = 4; break;
					case 14:	pref = 1; break;
					case 15:	pref = 3; break;
					case 16:	pref = 2; break;
					default:	pref = 0; break;
					}

					if (pref != 0)
					{
						IKE_DH *d = GetIkeDh(ike->Engine, false, t->TransformId);
						if (d != NULL && (dh_pref == 0 || pref < dh_pref))
						{
							dh_alg = d;
							dh_pref = pref;
							dh_id = t->TransformId;
						}
					}
				}
				break;
			}
		}

		if (crypto != NULL && prf != NULL && integ != NULL && dh_alg != NULL)
		{
			// Complete proposal found
			setting->Crypto = crypto;
			setting->CryptoId = crypto_id;
			setting->CryptoKeySize = crypto_key_size;
			setting->Hash = integ;
			setting->HashId = integ_id;
			setting->V2Prf = prf;
			setting->V2IntegId = integ_id;
			setting->V2IntegIcvSize = integ_icv_size;
			setting->Dh = dh_alg;
			setting->DhId = dh_id;
			setting->LifeSeconds = INFINITE;
			setting->LifeKilobytes = INFINITE;

			return true;
		}

		if (crypto != NULL && prf != NULL && integ != NULL && dh_alg == NULL)
		{
			// Everything matches except the DH group
			dh_unsupported_only = true;
		}
	}

	if (dh_unsupported_only)
	{
		// Answer with our most preferred group for an INVALID_KE_PAYLOAD
		*invalid_ke_group = IKE_P1_DH_GROUP_2048_MODP;
	}

	return false;
}

// Select an ESP Child SA proposal carried in the IKE_AUTH exchange
bool IkeV2SelectChildSaProposal(IKE_SERVER *ike, IKE_PACKET_PAYLOAD *sa_payload,
								IPSEC_SA_TRANSFORM_SETTING *setting, UINT *client_spi)
{
	IKEV2_PACKET_SA_PAYLOAD *sa;
	UINT i, j;
	// Validate arguments
	if (ike == NULL || sa_payload == NULL || setting == NULL || client_spi == NULL)
	{
		return false;
	}

	if (sa_payload->PayloadType != IKEV2_PAYLOAD_SA)
	{
		return false;
	}

	sa = &sa_payload->Payload.SaV2;

	for (i = 0; i < LIST_NUM(sa->ProposalList); i++)
	{
		IKEV2_PROPOSAL *proposal = LIST_DATA(sa->ProposalList, i);

		if (proposal->ProtocolId != IKE_PROTOCOL_ID_IPSEC_ESP)
		{
			continue;
		}

		if (proposal->Spi == NULL || proposal->Spi->Size != 4)
		{
			continue;
		}

		{
			UCHAR *spi = (UCHAR *)proposal->Spi->Buf;
			*client_spi = (UINT)(((UINT)spi[0] << 24) | ((UINT)spi[1] << 16) | ((UINT)spi[2] << 8) | (UINT)spi[3]);
		}

		{
			IKE_CRYPTO *crypto = NULL;
			UINT crypto_id = 0, crypto_key_size = 0;
			IKE_HASH *integ = NULL;
			UINT integ_id = 0;

			for (j = 0; j < LIST_NUM(proposal->TransformList); j++)
			{
				IKEV2_TRANSFORM *t = LIST_DATA(proposal->TransformList, j);

				if (t->TransformType == IKEV2_TRANSFORM_TYPE_ENCR)
				{
					if (t->TransformId == IKEV2_ENCR_AES_CBC)
					{
						UINT key_bits = IkeV2GetKeyLengthBit(proposal);
						if (key_bits == 0)
						{
							key_bits = 128;
						}

						if (key_bits == 128 || key_bits == 192 || key_bits == 256)
						{
							if (crypto == NULL)
							{
								crypto = GetIkeCrypto(ike->Engine, true, IKE_TRANSFORM_ID_P2_ESP_AES);
								crypto_id = IKEV2_ENCR_AES_CBC;
								crypto_key_size = key_bits / 8;
							}
						}
					}
					else if (t->TransformId == IKEV2_ENCR_3DES)
					{
						if (crypto == NULL)
						{
							crypto = GetIkeCrypto(ike->Engine, true, IKE_TRANSFORM_ID_P2_ESP_3DES);
							crypto_id = IKEV2_ENCR_3DES;
							crypto_key_size = 24;
						}
					}
				}
				else if (t->TransformType == IKEV2_TRANSFORM_TYPE_INTEG)
				{
					// The current ESP data path always truncates the
					// authentication tag to 12 bytes, so only the 96 bit
					// algorithms are accepted for now
					if (t->TransformId == IKEV2_AUTH_HMAC_SHA1_96 && integ == NULL)
					{
						integ = GetIkeHash(ike->Engine, true, IKE_P2_HMAC_SHA1_96);
						integ_id = IKEV2_AUTH_HMAC_SHA1_96;
					}
					else if (t->TransformId == IKEV2_AUTH_HMAC_MD5_96 && integ == NULL)
					{
						integ = GetIkeHash(ike->Engine, true, IKE_P2_HMAC_MD5_96);
						integ_id = IKEV2_AUTH_HMAC_MD5_96;
					}
				}
			}

			if (crypto != NULL && integ != NULL)
			{
				Zero(setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

				setting->Crypto = crypto;
				setting->CryptoId = crypto_id;
				setting->CryptoKeySize = crypto_key_size;
				setting->Hash = integ;
				setting->HashId = integ_id;
				setting->Dh = NULL;
				setting->LifeSeconds = IKEV2_CHILD_LIFETIME_DEFAULT;
				setting->LifeKilobytes = INFINITE;
				// The caller adjusts the capsule mode depending on the NAT
				// detection result and the transport mode notification
				setting->CapsuleMode = IKE_P2_CAPSULE_TUNNEL;

				return true;
			}
		}
	}

	return false;
}

// Build the SA payload of the IKE_SA_INIT response from the selected setting
IKE_PACKET_PAYLOAD *IkeV2BuildIkeSaResponseProposal(IKE_SERVER *ike, IKE_SA_TRANSFORM_SETTING *setting)
{
	LIST *transform_list;
	LIST *proposal_list;
	USHORT prf_id, integ_id;
	// Validate arguments
	if (ike == NULL || setting == NULL)
	{
		return NULL;
	}

	// Express the PRF preference back as a transform ID
	if (setting->V2Prf == GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA2_256))
	{
		prf_id = IKEV2_PRF_HMAC_SHA2_256;
	}
	else if (setting->V2Prf == GetIkeHash(ike->Engine, false, IKE_P1_HASH_SHA1))
	{
		prf_id = IKEV2_PRF_HMAC_SHA1;
	}
	else
	{
		prf_id = IKEV2_PRF_HMAC_MD5;
	}

	integ_id = (USHORT)setting->V2IntegId;

	transform_list = NewListFast(NULL);

	// Encryption algorithm
	if (setting->CryptoId == IKEV2_ENCR_AES_CBC)
	{
		IKEV2_TRANSFORM *t = IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_ENCR, IKEV2_ENCR_AES_CBC);
		Add(t->AttributeList, IkeV2NewTransformAttributeTv(IKEV2_SA_ATTR_KEY_LENGTH,
			(USHORT)(setting->CryptoKeySize * 8)));
		Add(transform_list, t);
	}
	else
	{
		Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_ENCR, IKEV2_ENCR_3DES));
	}

	// PRF
	Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_PRF, prf_id));

	// Integrity algorithm
	Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_INTEG, integ_id));

	// DH group
	Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_DH, (USHORT)setting->DhId));

	// For an initial IKE SA negotiation the SPI size must be zero
	proposal_list = NewListSingle(IkeV2NewProposal(1, IKE_PROTOCOL_ID_IKE, NULL, 0, transform_list));

	return IkeV2NewSaPayload(proposal_list);
}

// Build the SA payload of the Child SA response (SAr2) from the selected setting
IKE_PACKET_PAYLOAD *IkeV2BuildChildSaResponseProposal(IKE_SERVER *ike, IPSEC_SA_TRANSFORM_SETTING *setting, UINT our_spi)
{
	LIST *transform_list;
	UCHAR spi_be[4];
	// Validate arguments
	if (ike == NULL || setting == NULL)
	{
		return NULL;
	}

	transform_list = NewListFast(NULL);

	if (setting->CryptoId == IKEV2_ENCR_AES_CBC)
	{
		IKEV2_TRANSFORM *t = IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_ENCR, IKEV2_ENCR_AES_CBC);
		Add(t->AttributeList, IkeV2NewTransformAttributeTv(IKEV2_SA_ATTR_KEY_LENGTH,
			(USHORT)(setting->CryptoKeySize * 8)));
		Add(transform_list, t);
	}
	else
	{
		Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_ENCR, IKEV2_ENCR_3DES));
	}

	Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_INTEG, (USHORT)setting->HashId));

	// No extended sequence numbers
	Add(transform_list, IkeV2NewTransform(IKEV2_TRANSFORM_TYPE_ESN, IKEV2_ESN_NO));

	spi_be[0] = (UCHAR)((our_spi >> 24) & 0xff);
	spi_be[1] = (UCHAR)((our_spi >> 16) & 0xff);
	spi_be[2] = (UCHAR)((our_spi >> 8) & 0xff);
	spi_be[3] = (UCHAR)(our_spi & 0xff);

	return IkeV2NewSaPayload(NewListSingle(IkeV2NewProposal(1, IKE_PROTOCOL_ID_IPSEC_ESP,
		spi_be, sizeof(spi_be), transform_list)));
}

//// NAT detection

// Evaluate the NAT detection notifies of an IKE_SA_INIT request
void IkeV2CheckNatD(IKE_SERVER *ike, IKE_PACKET *pr, UDPPACKET *p, IKE_PACKET *header, IKE_SA *sa)
{
	IKE_PACKET_PAYLOAD *notify_src, *notify_dst;
	BUF *calc_src, *calc_dst;
	IKE_HASH *sha1;
	// Validate arguments
	if (ike == NULL || pr == NULL || p == NULL || header == NULL || sa == NULL)
	{
		return;
	}

	sha1 = IkeV2GetSha1(ike);

	notify_src = IkeV2GetNotifyPayload(pr, IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, 0);
	notify_dst = IkeV2GetNotifyPayload(pr, IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP, 0);

	if (notify_src == NULL || notify_dst == NULL)
	{
		// The peer does not support NAT traversal: assume no NAT
		sa->V2NatDetected = false;
		return;
	}

	// During IKE_SA_INIT the responder SPI is still zero from the point of
	// view of the initiator, so the hashes are computed with SPIr = 0
	calc_src = IkeCalcNatDetectHash(ike, sha1, header->InitiatorCookie, 0, &p->SrcIP, p->SrcPort);
	calc_dst = IkeCalcNatDetectHash(ike, sha1, header->InitiatorCookie, 0, &p->DstIP, p->DestPort);

	// The initiator is behind a NAT when the observed source address does
	// not match its own view; our side is behind a NAT when the observed
	// destination address does not match the initiator's view of us
	if (IkeV2CompareNotifyData(notify_src, calc_src) == false ||
		IkeV2CompareNotifyData(notify_dst, calc_dst) == false)
	{
		sa->V2NatDetected = true;
	}
	else
	{
		sa->V2NatDetected = false;
	}

	FreeBuf(calc_src);
	FreeBuf(calc_dst);
}

// Compare the data of a NAT detection notify with a calculated hash
static bool IkeV2CompareNotifyData(IKE_PACKET_PAYLOAD *notify_payload, BUF *hash)
{
	IKE_PACKET_NOTICE_PAYLOAD *n;
	// Validate arguments
	if (notify_payload == NULL || hash == NULL)
	{
		return false;
	}

	n = &notify_payload->Payload.Notice;

	if (n->MessageData == NULL || n->MessageData->Size != hash->Size)
	{
		return false;
	}

	return (Cmp(n->MessageData->Buf, hash->Buf, hash->Size) == 0) ? true : false;
}

//// Encrypted payload handling (RFC 7296 section 3.14)

// Decrypt the Encrypted (SK) payload of a received request in place.
// On success header->PayloadList is replaced with the decrypted inner
// payload list. The payload list passed in the header is consumed either way.
bool IkeV2RecvEncrypted(IKE_SERVER *ike, IKE_SA *sa, UDPPACKET *p, IKE_PACKET *header)
{
	BUF *sk_body = NULL;
	UINT iv_size, icv_size, cipher_size, pad_len;
	UCHAR icv_calc[IKE_MAX_HASH_SIZE];
	UCHAR first_payload_type;
	BUF *dec = NULL;
	LIST *inner = NULL;
	IKE_CRYPTO_PARAM cp;
	bool ret = false;
	// Validate arguments
	if (ike == NULL || sa == NULL || p == NULL || header == NULL)
	{
		return false;
	}

	if (sa->V2KeyEi == NULL || sa->TransformSetting.Crypto == NULL || sa->TransformSetting.Hash == NULL)
	{
		return false;
	}

	// An IKEv2 encrypted message carries exactly one top level payload: the
	// Encrypted (SK) payload. The generic payload chain parser of IkeParse
	// cannot be used here because the NextPayload field of the SK payload
	// points to the first INNER payload, not to a sibling: extract the SK
	// payload manually instead.
	if (p->Size < sizeof(IKE_HEADER) + 4)
	{
		return false;
	}

	if (header->MessageSize < sizeof(IKE_HEADER) + 4 || header->MessageSize > p->Size)
	{
		return false;
	}

	{
		UCHAR *dp = (UCHAR *)p->Data;
		USHORT sk_payload_size = (USHORT)(((USHORT)dp[sizeof(IKE_HEADER) + 2] << 8) |
			(USHORT)dp[sizeof(IKE_HEADER) + 3]);

		first_payload_type = dp[sizeof(IKE_HEADER)];

		if (sk_payload_size < 5 || (UINT)sk_payload_size != header->MessageSize - sizeof(IKE_HEADER))
		{
			return false;
		}

		// SK payload body: IV || ciphertext || ICV
		sk_body = MemToBuf(dp + sizeof(IKE_HEADER) + 4, (UINT)sk_payload_size - 4);
	}

	iv_size = sa->TransformSetting.Crypto->BlockSize;
	icv_size = sa->TransformSetting.V2IntegIcvSize;

	if (icv_size == 0 || sk_body->Size < iv_size + iv_size + icv_size)
	{
		FreeBuf(sk_body);
		return false;
	}

	cipher_size = sk_body->Size - iv_size - icv_size;

	if (cipher_size % iv_size != 0)
	{
		FreeBuf(sk_body);
		return false;
	}

	// Verify the ICV: integrity over the whole message (IKE header,
	// SK payload header, IV and ciphertext) with SK_ai (RFC 7296 section 3.14)
	IkeHMac(sa->TransformSetting.Hash, icv_calc, sa->V2SkAi, sa->TransformSetting.Hash->HashSize,
		p->Data, p->Size - icv_size);

	if (Cmp(icv_calc, ((UCHAR *)p->Data) + p->Size - icv_size, icv_size) != 0)
	{
		IPsecLog(ike, sa->IkeClient, sa, NULL, "LI2_SK_ICV_ERROR");
		FreeBuf(sk_body);
		return false;
	}

	// Decrypt the ciphertext with SK_ei
	Zero(&cp, sizeof(cp));
	Copy(cp.Iv, sk_body->Buf, iv_size);
	cp.Key = sa->V2KeyEi;

	dec = IkeDecrypt(((UCHAR *)sk_body->Buf) + iv_size, cipher_size, &cp);

	if (dec == NULL)
	{
		FreeBuf(sk_body);
		return false;
	}

	// Strip the padding: the last plaintext byte holds the pad length
	if (dec->Size < 1)
	{
		goto cleanup;
	}

	pad_len = ((UCHAR *)dec->Buf)[dec->Size - 1];

	if (pad_len + 1 > dec->Size)
	{
		goto cleanup;
	}


	dec->Size -= pad_len + 1;

	// Parse the inner payload list
	inner = IkeParsePayloadListEx(dec->Buf, dec->Size, first_payload_type, NULL);

	if (inner == NULL)
	{
		goto cleanup;
	}

	// Hand over the decrypted payload list to the caller's packet header
	IkeFreePayloadList(header->PayloadList);
	header->PayloadList = inner;
	inner = NULL;

	ret = true;

cleanup:
	FreeBuf(dec);
	FreeBuf(sk_body);

	if (inner != NULL)
	{
		IkeFreePayloadList(inner);
	}

	return ret;
}

// Send an encrypted response: wrap the payload list into an SK payload,
// cache the raw bytes for retransmission and send the packet.
// This function takes the ownership of payload_list.
void IkeV2SendEncryptedResponse(IKE_SERVER *ike, IKE_SA *sa, UCHAR exchange_type, UINT message_id, LIST *payload_list)
{
	BUF *inner = NULL;
	BUF *plain = NULL, *body = NULL, *msg = NULL;
	UINT blocksize, icv_size, data_size, pad_len, i;
	UCHAR iv[IKE_MAX_BLOCK_SIZE];
	UCHAR icv[IKE_MAX_HASH_SIZE];
	IKE_CRYPTO_PARAM cp;
	IKE_HEADER h;
	UCHAR sk_header[4];
	UINT sk_payload_size, msg_size;
	// Validate arguments
	if (ike == NULL || sa == NULL || payload_list == NULL)
	{
		goto cleanup;
	}

	if (sa->V2KeyEr == NULL || sa->TransformSetting.Crypto == NULL || sa->TransformSetting.Hash == NULL)
	{
		goto cleanup;
	}

	inner = IkeBuildPayloadList(payload_list);

	if (inner == NULL)
	{
		goto cleanup;
	}

	blocksize = sa->TransformSetting.Crypto->BlockSize;
	icv_size = sa->TransformSetting.V2IntegIcvSize;

	// Plaintext: inner payloads || padding || pad length (1 byte),
	// the whole plaintext must be a multiple of the cipher block size
	data_size = inner->Size;
	pad_len = (blocksize - ((data_size + 1) % blocksize)) % blocksize;

	plain = NewBuf();
	WriteBufBuf(plain, inner);

	for (i = 0; i < pad_len; i++)
	{
		UCHAR zero = 0;
		WriteBuf(plain, &zero, 1);
	}

	{
		UCHAR pad_len_byte = (UCHAR)pad_len;
		WriteBuf(plain, &pad_len_byte, 1);
	}

	// Random IV
	Rand(iv, blocksize);

	// Encrypt with SK_er
	Zero(&cp, sizeof(cp));
	cp.Key = sa->V2KeyEr;
	Copy(cp.Iv, iv, blocksize);

	body = IkeEncrypt(plain->Buf, plain->Size, &cp);

	if (body == NULL)
	{
		goto cleanup;
	}

	// Compose the message header fields
	sk_payload_size = sizeof(sk_header) + blocksize + body->Size + icv_size;
	msg_size = sizeof(h) + sk_payload_size;

	Zero(&h, sizeof(h));
	h.InitiatorCookie = Endian64(sa->InitiatorCookie);
	h.ResponderCookie = Endian64(sa->ResponderCookie);
	h.NextPayload = IKEV2_PAYLOAD_ENCRYPTED;
	h.MajorVersion = IKE_MAJOR_VERSION_2;
	h.MinorVersion = 0;
	h.ExchangeType = exchange_type;
	h.Flag = IKE_HEADER_V2_FLAG_RESPONSE;
	h.MessageId = Endian32(message_id);
	h.MessageSize = Endian32(msg_size);

	sk_header[0] = IkeGetFirstPayloadType(payload_list);
	sk_header[1] = 0;
	sk_header[2] = (UCHAR)((sk_payload_size >> 8) & 0xff);
	sk_header[3] = (UCHAR)(sk_payload_size & 0xff);

	// Compose the message without the ICV: the ICV covers the whole message
	// (IKE header, SK payload header, IV and ciphertext, RFC 7296 section 3.14)
	msg = NewBuf();
	WriteBuf(msg, &h, sizeof(h));
	WriteBuf(msg, sk_header, sizeof(sk_header));
	WriteBuf(msg, iv, blocksize);
	WriteBufBuf(msg, body);

	// ICV over the whole message with SK_ar
	IkeHMac(sa->TransformSetting.Hash, icv, sa->V2SkAr, sa->TransformSetting.Hash->HashSize,
		msg->Buf, msg->Size);

	WriteBuf(msg, icv, icv_size);

	// Cache the response for retransmission
	if (sa->SendBuffer != NULL)
	{
		FreeBuf(sa->SendBuffer);
	}

	sa->SendBuffer = CloneBuf(msg);
	sa->NextSendTick = ike->Now + (UINT64)IKE_SA_RESEND_INTERVAL;
	AddInterrupt(ike->Interrupts, sa->NextSendTick);

	// Send (IkeSendUdpPacket takes the ownership of the data buffer)
	IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &sa->IkeClient->ServerIP, sa->IkeClient->ServerPort,
		&sa->IkeClient->ClientIP, sa->IkeClient->ClientPort, Clone(msg->Buf, msg->Size), msg->Size);

cleanup:
	FreeBuf(inner);
	FreeBuf(plain);
	FreeBuf(body);
	FreeBuf(msg);

	if (payload_list != NULL)
	{
		IkeFreePayloadList(payload_list);
	}
}

// Send an encrypted response that contains only a notify payload
void IkeV2SendEncryptedNotify(IKE_SERVER *ike, IKE_SA *sa, UCHAR exchange_type, UINT message_id,
							  USHORT notify_type, void *notify_data, UINT notify_data_size)
{
	LIST *payload_list;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	payload_list = NewListSingle(IkeV2NewNotifyPayload(0, notify_type, NULL, 0, notify_data, notify_data_size));

	IkeV2SendEncryptedResponse(ike, sa, exchange_type, message_id, payload_list);
}

// Send a plain (unencrypted) response that contains only an error notify.
// Used to answer IKE_SA_INIT requests that cannot be processed.
void IkeV2SendPlainNotifyResponse(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET *header,
								   USHORT notify_type, void *notify_data, UINT notify_data_size)
{
	IKE_PACKET_PAYLOAD *notify;
	LIST *payload_list;
	IKE_PACKET *ps;
	BUF *buf;
	// Validate arguments
	if (ike == NULL || c == NULL || header == NULL)
	{
		return;
	}

	notify = IkeV2NewNotifyPayload(0, notify_type, NULL, 0, notify_data, notify_data_size);

	if (notify == NULL)
	{
		return;
	}

	payload_list = NewListSingle(notify);

	ps = IkeV2New(header->InitiatorCookie, header->ResponderCookie, IKE_EXCHANGE_TYPE_IKE_SA_INIT,
		header->MessageId, false, true, payload_list);

	if (ps == NULL)
	{
		IkeFreePayloadList(payload_list);
		return;
	}

	buf = IkeBuild(ps, NULL);

	IkeFree(ps);

	if (buf == NULL)
	{
		return;
	}

	IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &c->ServerIP, c->ServerPort, &c->ClientIP, c->ClientPort,
		Clone(buf->Buf, buf->Size), buf->Size);

	FreeBuf(buf);
}

//// ESP anti-replay window (RFC 4303 section 3.4.3)
//
// The bitmap bit at offset k means "the sequence number (last_seq - k) has
// been authenticated". A sequence number is acceptable when it is newer than
// the window base and its bit is still clear.

// Check whether the sequence number would be accepted
bool IkeV2EspReplayCheck(IPSECSA *sa, UINT seq)
{
	UINT offset;
	// Validate arguments
	if (sa == NULL || seq == 0)
	{
		return false;
	}

	if (sa->V2ReplayLastSeq == 0 || seq > sa->V2ReplayLastSeq)
	{
		// To the right of the window: always acceptable
		return true;
	}

	offset = sa->V2ReplayLastSeq - seq;

	if (offset >= IKEV2_ESP_REPLAY_WINDOW_SIZE)
	{
		// Too old
		return false;
	}

	if ((sa->V2ReplayWindow[offset / 8] & (0x80 >> (offset % 8))) != 0)
	{
		// Duplicate
		return false;
	}

	return true;
}

// Mark a sequence number as authenticated
void IkeV2EspReplayUpdate(IPSECSA *sa, UINT seq)
{
	UINT shift;
	UINT i;
	// Validate arguments
	if (sa == NULL || seq == 0)
	{
		return;
	}

	if (sa->V2ReplayLastSeq == 0 || seq > sa->V2ReplayLastSeq)
	{
		shift = seq - sa->V2ReplayLastSeq;

		if (shift >= IKEV2_ESP_REPLAY_WINDOW_SIZE)
		{
			Zero(sa->V2ReplayWindow, sizeof(sa->V2ReplayWindow));
		}
		else
		{
			// Shift the whole bitmap right by "shift" bits so that the bit
			// offsets keep pointing at (last_seq - k)
			UCHAR tmp[IKEV2_ESP_REPLAY_WINDOW_SIZE / 8];
			Zero(tmp, sizeof(tmp));

			for (i = 0; i < sizeof(sa->V2ReplayWindow); i++)
			{
				UINT bit;
				for (bit = 0; bit < 8; bit++)
				{
					if ((sa->V2ReplayWindow[i] & (0x80 >> bit)) != 0)
					{
						UINT new_offset = i * 8 + bit + shift;

						if (new_offset < IKEV2_ESP_REPLAY_WINDOW_SIZE)
						{
							tmp[new_offset / 8] |= (0x80 >> (new_offset % 8));
						}
					}
				}
			}

			Copy(sa->V2ReplayWindow, tmp, sizeof(sa->V2ReplayWindow));
		}

		sa->V2ReplayLastSeq = seq;
	}

	{
		UINT offset = sa->V2ReplayLastSeq - seq;

		if (offset < IKEV2_ESP_REPLAY_WINDOW_SIZE)
		{
			sa->V2ReplayWindow[offset / 8] |= (0x80 >> (offset % 8));
		}
	}
}

//// Certificate signature AUTH (RFC 7427 digital signature method)

// Build an AUTH payload with the RSA digital signature method (14).
// The signature covers the same signed octets as the PSK method; the
// authentication data is the DER hash AlgorithmIdentifier followed by the
// RSASSA-PKCS1-v1_5 signature over SHA-256 (or SHA-1) of the octets.
// Returns NULL when no server certificate is configured or the key is not RSA.
IKE_PACKET_PAYLOAD *IkeV2BuildSignatureAuth(IKE_SERVER *ike, IKE_SA *sa, BUF *real_message, BUF *nonce,
											void *skp, UINT skp_size, BUF *id_body, bool prefer_sha256)
{
	BUF *octets;
	UCHAR sign_data[512];
	UINT sign_size = 0;
	BUF *auth_data = NULL;
	IKE_PACKET_PAYLOAD *ret = NULL;
	X *server_x = NULL;
	K *server_k = NULL;
	bool ok = false;
	// ASN.1 AlgorithmIdentifier without parameters (RFC 7427 section 5.2)
	static const UCHAR asn_sha256[] =
	{
		0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01,
	};
	static const UCHAR asn_sha1[] =
	{
		0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
		0x1a,
	};
	const UCHAR *asn = NULL;
	UINT asn_size = 0;
	// Validate arguments
	if (ike == NULL || sa == NULL || real_message == NULL || nonce == NULL || id_body == NULL)
	{
		return NULL;
	}

	if (ike->Cedar == NULL)
	{
		return NULL;
	}

	// Clone the server certificate and key under the cedar lock
	Lock(ike->Cedar->lock);
	{
		if (ike->Cedar->ServerX != NULL && ike->Cedar->ServerK != NULL)
		{
			server_x = CloneX(ike->Cedar->ServerX);
			server_k = CloneK(ike->Cedar->ServerK);
		}
	}
	Unlock(ike->Cedar->lock);

	if (server_x == NULL || server_k == NULL)
	{
		goto cleanup;
	}

	octets = IkeV2CalcSignedOctets(sa, real_message, nonce, skp, skp_size, id_body);

	if (octets == NULL)
	{
		goto cleanup;
	}

	Zero(sign_data, sizeof(sign_data));

	if (prefer_sha256)
	{
		ok = RsaSignSha256(sign_data, sizeof(sign_data), &sign_size, octets->Buf, octets->Size, server_k);
		asn = asn_sha256;
		asn_size = sizeof(asn_sha256);
	}
	else
	{
		// Legacy RSA signature with SHA-1 (RFC 7296 method 1 semantics but
		// announced as digital signature with the SHA-1 hash identifier)
		UINT i;

		ok = RsaSignEx(sign_data, octets->Buf, octets->Size, server_k, sizeof(sign_data) * 8);
		asn = asn_sha1;
		asn_size = sizeof(asn_sha1);

		if (ok)
		{
			// RsaSignEx right-zero-pads: derive the modulus size from the
			// last non-zero byte (a PKCS#1 v1.5 signature never ends in 0x00)
			sign_size = 0;
			for (i = sizeof(sign_data); i >= 1; i--)
			{
				if (sign_data[i - 1] != 0)
				{
					sign_size = i;
					break;
				}
			}
		}
	}

	FreeBuf(octets);

	if (ok == false || sign_size == 0)
	{
		goto cleanup;
	}

	// Authentication data: length-prefixed ASN.1 hash AlgorithmIdentifier
	// followed by the signature (RFC 7427 section 3: the first byte carries
	// the length of the variable ASN.1 part)
	auth_data = NewBuf();
	{
		UCHAR asn_len = (UCHAR)asn_size;
		WriteBuf(auth_data, &asn_len, sizeof(asn_len));
	}
	WriteBuf(auth_data, (void *)asn, asn_size);
	WriteBuf(auth_data, sign_data, sign_size);

	ret = IkeV2NewAuthPayload(IKEV2_AUTH_METHOD_DSIG, auth_data->Buf, auth_data->Size);

	FreeBuf(auth_data);

cleanup:
	if (server_x != NULL)
	{
		FreeX(server_x);
	}
	if (server_k != NULL)
	{
		FreeK(server_k);
	}

	return ret;
}

//// EAP (RFC 3748) and EAP-MSCHAPv2 helpers

// Parse a complete EAP message from the payload data.
// Returns the code, the identifier and, for typed messages, the type and
// the type data as a newly allocated BUF.
static bool IkeV2ParseEapMessage(BUF *data, UCHAR *code, UCHAR *id, UCHAR *type, BUF **type_data)
{
	UCHAR *dp;
	UINT len;
	// Validate arguments
	if (data == NULL || data->Size < 4 || code == NULL || id == NULL || type == NULL || type_data == NULL)
	{
		return false;
	}

	dp = (UCHAR *)data->Buf;
	len = ((UINT)dp[2] << 8) | (UINT)dp[3];

	if (len < 4 || len > data->Size)
	{
		return false;
	}

	*code = dp[0];
	*id = dp[1];

	if (len >= 5)
	{
		*type = dp[4];
		*type_data = MemToBuf(dp + 5, len - 5);
	}
	else
	{
		*type = 0;
		*type_data = NULL;
	}

	return true;
}

// Build an EAP payload. Pass type 0 for a code-only message (Success / Failure)
static IKE_PACKET_PAYLOAD *IkeV2NewEapPayload(UCHAR code, UCHAR id, UCHAR type, void *type_data, UINT type_data_size)
{
	BUF *b;
	UCHAR hdr[4];
	UINT len = 4 + (type != 0 ? 1 + type_data_size : 0);
	IKE_PACKET_PAYLOAD *ret;

	hdr[0] = code;
	hdr[1] = id;
	hdr[2] = (UCHAR)((len >> 8) & 0xff);
	hdr[3] = (UCHAR)(len & 0xff);

	b = NewBuf();
	WriteBuf(b, hdr, sizeof(hdr));

	if (type != 0)
	{
		UCHAR t = type;
		WriteBuf(b, &t, 1);

		if (type_data != NULL && type_data_size != 0)
		{
			WriteBuf(b, type_data, type_data_size);
		}
	}

	ret = IkeNewDataPayload(IKEV2_PAYLOAD_EAP, b->Buf, b->Size);

	FreeBuf(b);

	return ret;
}

// Build an EAP-MSCHAPv2 Challenge request (OpCode 1)
static IKE_PACKET_PAYLOAD *IkeV2NewEapMschapV2Challenge(UCHAR eap_id, UCHAR mschap_id, UCHAR *challenge16, char *name)
{
	BUF *ms = NewBuf();
	UCHAR head[5];
	UINT ms_len = 4 + 1 + IKEV2_MSCHAPV2_CHALLENGE_SIZE + StrLen(name);
	IKE_PACKET_PAYLOAD *ret;

	head[0] = 1;	// OpCode: Challenge
	head[1] = mschap_id;
	head[2] = (UCHAR)((ms_len >> 8) & 0xff);
	head[3] = (UCHAR)(ms_len & 0xff);
	head[4] = IKEV2_MSCHAPV2_CHALLENGE_SIZE;

	WriteBuf(ms, head, sizeof(head));
	WriteBuf(ms, challenge16, IKEV2_MSCHAPV2_CHALLENGE_SIZE);
	WriteBuf(ms, name, StrLen(name));

	ret = IkeV2NewEapPayload(IKEV2_EAP_CODE_REQUEST, eap_id, IKEV2_EAP_TYPE_MSCHAPV2, ms->Buf, ms->Size);

	FreeBuf(ms);

	return ret;
}

// Build an EAP-MSCHAPv2 Success request (OpCode 3) carrying the S= string
static IKE_PACKET_PAYLOAD *IkeV2NewEapMschapV2Success(UCHAR eap_id, UCHAR mschap_id, UCHAR *server_response_20)
{
	char hex[IKEV2_MSCHAPV2_S_RESPONSE_SIZE * 2 + 1];
	char msg[MAX_SIZE * 2];
	BUF *ms = NewBuf();
	UCHAR head[4];
	UINT ms_len;
	IKE_PACKET_PAYLOAD *ret;

	BinToStr(hex, sizeof(hex), server_response_20, IKEV2_MSCHAPV2_S_RESPONSE_SIZE);
	Format(msg, sizeof(msg), "S=%s M=Welcome", hex);

	ms_len = 4 + StrLen(msg);

	head[0] = 3;	// OpCode: Success
	head[1] = mschap_id;
	head[2] = (UCHAR)((ms_len >> 8) & 0xff);
	head[3] = (UCHAR)(ms_len & 0xff);

	WriteBuf(ms, head, sizeof(head));
	WriteBuf(ms, msg, StrLen(msg));

	ret = IkeV2NewEapPayload(IKEV2_EAP_CODE_REQUEST, eap_id, IKEV2_EAP_TYPE_MSCHAPV2, ms->Buf, ms->Size);

	FreeBuf(ms);

	return ret;
}

// Parse an EAP-MSCHAPv2 Response (OpCode 2):
//   MsChapId(1) MsLength(2) ValueSize(1)=49 PeerChallenge(16) Reserved(8)
//   NTResponse(24) Flags(1) Name(...)
static bool IkeV2ParseEapMschapV2Response(BUF *type_data, UCHAR *peer_challenge, UCHAR *nt_response,
										  char *name, UINT name_size)
{
	UCHAR *d;
	UINT pos;
	UINT name_len;
	// Validate arguments
	if (type_data == NULL || type_data->Size < 5 + 1 + 49 || peer_challenge == NULL ||
		nt_response == NULL || name == NULL)
	{
		return false;
	}

	d = (UCHAR *)type_data->Buf;

	if (d[0] != 2)	// OpCode: Response
	{
		return false;
	}

	pos = 4;

	if (d[pos] != 49)
	{
		return false;
	}
	pos++;

	Copy(peer_challenge, d + pos, 16);
	pos += 16;
	pos += 8;	// Reserved
	Copy(nt_response, d + pos, IKEV2_MSCHAPV2_NT_RESPONSE_SIZE);
	pos += IKEV2_MSCHAPV2_NT_RESPONSE_SIZE;
	pos += 1;	// Flags

	name_len = type_data->Size - pos;
	if (name_len >= name_size)
	{
		name_len = name_size - 1;
	}

	Copy(name, d + pos, name_len);
	name[name_len] = 0;

	return true;
}

// Derive the 64 byte EAP MSK from the MSCHAPv2 exchange (RFC 3079 section 3.3).
// The layout matches the strongSwan implementation: two 16 byte keys followed
// by 32 zero bytes.
static void IkeV2CalcMskFromMsChapV2(UCHAR *nt_hash_hash, UCHAR *nt_response, UCHAR *msk64)
{
	char *magic1 = "This is the MPPE Master Key";
	char *magic2 = "On the client side, this is the send key; on the server side, it is the receive key.";
	char *magic3 = "On the client side, this is the receive key; on the server side, it is the send key.";
	UCHAR shapad1[40];
	UCHAR shapad2[40];
	UCHAR master[SHA1_SIZE];
	BUF *b;
	UCHAR i;

	Zero(shapad1, sizeof(shapad1));
	for (i = 0; i < sizeof(shapad2); i++)
	{
		shapad2[i] = 0xF2;
	}

	// MasterKey = SHA1(PasswordHashHash || NTResponse || magic1)[0..15]
	b = NewBuf();
	WriteBuf(b, nt_hash_hash, 16);
	WriteBuf(b, nt_response, IKEV2_MSCHAPV2_NT_RESPONSE_SIZE);
	WriteBuf(b, magic1, StrLen(magic1));
	Sha1(master, b->Buf, b->Size);
	FreeBuf(b);

	// First key with magic2
	b = NewBuf();
	WriteBuf(b, master, 16);
	WriteBuf(b, shapad1, sizeof(shapad1));
	WriteBuf(b, magic2, StrLen(magic2));
	WriteBuf(b, shapad2, sizeof(shapad2));
	Sha1(msk64 + 0, b->Buf, b->Size);
	FreeBuf(b);

	// Second key with magic3
	b = NewBuf();
	WriteBuf(b, master, 16);
	WriteBuf(b, shapad1, sizeof(shapad1));
	WriteBuf(b, magic3, StrLen(magic3));
	WriteBuf(b, shapad2, sizeof(shapad2));
	Sha1(msk64 + 16, b->Buf, b->Size);
	FreeBuf(b);

	// 32 bytes of zero padding
	Zero(msk64 + 32, 32);
}

// Verify an MSCHAPv2 NT-Response against the user database of the target
// virtual hub and derive the material needed for the EAP MSK
static bool IkeV2MsChapV2VerifyHubUser(IKE_SERVER *ike, char *username,
									   UCHAR *server_challenge, UCHAR *peer_challenge, UCHAR *nt_response,
									   UCHAR *nt_hash_hash, UCHAR *server_response_20)
{
	ETHERIP_ID d;
	HUB *hub;
	USER *u;
	bool ok = false;
	UCHAR challenge8[8];
	UCHAR expected[IKEV2_MSCHAPV2_NT_RESPONSE_SIZE];
	// Validate arguments
	if (ike == NULL || ike->Cedar == NULL || username == NULL || server_challenge == NULL ||
		peer_challenge == NULL || nt_response == NULL || nt_hash_hash == NULL || server_response_20 == NULL)
	{
		return false;
	}

	Zero(&d, sizeof(d));

	// Resolve "user@hub" with the IPsec default hub fallback
	PPPParseUsername(ike->Cedar, username, &d);

	if (IsEmptyStr(d.UserName))
	{
		return false;
	}

	hub = GetHub(ike->Cedar, d.HubName);

	if (hub == NULL)
	{
		return false;
	}

	AcLock(hub);
	{
		u = AcGetUser(hub, d.UserName);

		if (u != NULL)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_PASSWORD)
				{
					AUTHPASSWORD *auth = (AUTHPASSWORD *)u->AuthData;

					if (IsZero(auth->NtLmSecureHash, MD5_SIZE) == false)
					{
						MsChapV2_GenerateChallenge8(challenge8, peer_challenge, server_challenge, username);
						MsChapV2Client_GenerateResponse(expected, challenge8, auth->NtLmSecureHash);

						if (Cmp(expected, nt_response, IKEV2_MSCHAPV2_NT_RESPONSE_SIZE) == 0)
						{
							// The response matches: derive the MSK material
							GenerateNtPasswordHashHash(nt_hash_hash, auth->NtLmSecureHash);
							MsChapV2Server_GenerateResponse(server_response_20, nt_hash_hash, nt_response, challenge8);

							ok = true;
						}
					}
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
		}
	}
	AcUnlock(hub);

	ReleaseHub(hub);

	return ok;
}

// Start the asynchronous IPC connection into the virtual hub. The IPC login
// itself re-verifies the MSCHAPv2 response via the tagged password and the
// background thread additionally requests a virtual IP via DHCP (L3 mode).
static IPC_ASYNC *IkeV2NewIpcAsync(IKE_SERVER *ike, IKE_CLIENT *c, char *username_full,
								   UCHAR *server_challenge, UCHAR *peer_challenge, UCHAR *nt_response)
{
	IPC_PARAM param;
	ETHERIP_ID d;
	char password[MAX_PASSWORD_LEN + 8];
	char sc_hex[64], pc_hex[64], nt_hex[64], eap_hex[32];
	UINT64 eap_client_ptr = 0;
	// Validate arguments
	if (ike == NULL || c == NULL || username_full == NULL || server_challenge == NULL ||
		peer_challenge == NULL || nt_response == NULL)
	{
		return NULL;
	}

	Zero(&param, sizeof(param));
	Zero(&d, sizeof(d));

	PPPParseUsername(ike->Cedar, username_full, &d);

	// Build the MSCHAPv2 tagged password consumed by the in-proc login
	BinToStr(sc_hex, sizeof(sc_hex), server_challenge, IKEV2_MSCHAPV2_CHALLENGE_SIZE);
	BinToStr(pc_hex, sizeof(pc_hex), peer_challenge, IKEV2_MSCHAPV2_CHALLENGE_SIZE);
	BinToStr(nt_hex, sizeof(nt_hex), nt_response, IKEV2_MSCHAPV2_NT_RESPONSE_SIZE);
	BinToStr(eap_hex, sizeof(eap_hex), &eap_client_ptr, 8);

	Format(password, sizeof(password), "%s%s:%s:%s:%s:%s",
		IPC_PASSWORD_MSCHAPV2_TAG, username_full, sc_hex, pc_hex, nt_hex, eap_hex);

	StrCpy(param.ClientName, sizeof(param.ClientName), "IKEv2");
	StrCpy(param.Postfix, sizeof(param.Postfix), IKEV2_IPC_POSTFIX);
	StrCpy(param.HubName, sizeof(param.HubName), d.HubName);
	StrCpy(param.UserName, sizeof(param.UserName), d.UserName);
	StrCpy(param.Password, sizeof(param.Password), password);

	Copy(&param.ClientIp, &c->ClientIP, sizeof(IP));
	param.ClientPort = c->ClientPort;
	Copy(&param.ServerIp, &c->ServerIP, sizeof(IP));
	param.ServerPort = c->ServerPort;

	StrCpy(param.ClientHostname, sizeof(param.ClientHostname), "IKEv2 Client");
	StrCpy(param.CryptName, sizeof(param.CryptName), "IPsec (IKEv2)");

	param.Layer = IPC_LAYER_3;
	param.IsL3Mode = true;
	param.Mss = IKEV2_IPC_MSS;

	return NewIPCAsync(ike->Cedar, &param, ike->SockEvent);
}

// Wait (bounded) for the asynchronous IPC login and DHCP to complete
static IPC *IkeV2WaitIpcReady(IKE_CLIENT *c)
{
	UINT64 giveup = Tick64() + 4000;
	// Validate arguments
	if (c == NULL || c->V2IpcAsync == NULL)
	{
		return NULL;
	}

	while (c->V2IpcAsync->Done == false && Tick64() < giveup)
	{
		Sleep(25);
	}

	if (c->V2IpcAsync->Done && c->V2IpcAsync->Ipc != NULL)
	{
		return c->V2IpcAsync->Ipc;
	}

	return NULL;
}

// Build the CP (Configuration) reply payload carrying the virtual address
// obtained from the DHCP server of the hub
static IKE_PACKET_PAYLOAD *IkeV2NewCpReplyPayload(IPC_ASYNC *a)
{
	LIST *attrs;
	UCHAR v4[4];
	// Validate arguments
	if (a == NULL || a->Ipc == NULL || a->L3ClientAddressOption.ClientAddress == 0)
	{
		return NULL;
	}

	attrs = NewListFast(NULL);

	// The DHCP option list stores the addresses in network byte order in
	// memory (the same convention as UINTToIP): copy the raw bytes
	Copy(v4, &a->L3ClientAddressOption.ClientAddress, 4);
	Add(attrs, IkeV2NewCpAttribute(IKEV2_CP_ATTR_INTERNAL_IP4_ADDRESS, v4, 4));

	// Note: the INTERNAL_IP4_NETMASK attribute is deliberately not sent:
	// strongSwan rejects it and modern clients derive the prefix from the
	// subnet of the assigned address or use their own policy

	if (a->L3ClientAddressOption.DnsServer != 0)
	{
		Copy(v4, &a->L3ClientAddressOption.DnsServer, 4);
		Add(attrs, IkeV2NewCpAttribute(IKEV2_CP_ATTR_INTERNAL_IP4_DNS, v4, 4));
	}

	if (a->L3ClientAddressOption.DnsServer2 != 0)
	{
		Copy(v4, &a->L3ClientAddressOption.DnsServer2, 4);
		Add(attrs, IkeV2NewCpAttribute(IKEV2_CP_ATTR_INTERNAL_IP4_DNS, v4, 4));
	}

	return IkeV2NewCpPayload(IKEV2_CP_CFG_REPLY, attrs);
}

// Build the IDr payload body: our own address (same on every IKE_AUTH response)
static BUF *IkeV2BuildIdrBody(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *idr_type)
{
	UCHAR addr[16];
	UINT addr_size;
	BUF *idr_body;

	Zero(addr, sizeof(addr));

	if (IsIP6(&c->ServerIP))
	{
		Copy(addr, c->ServerIP.address, 16);
		addr_size = 16;
		*idr_type = IKE_ID_IPV6_ADDR;
	}
	else
	{
		Copy(addr, IPV4(c->ServerIP.address), IPV4_SIZE);
		addr_size = IPV4_SIZE;
		*idr_type = IKE_ID_IPV4_ADDR;
	}

	idr_body = NewBuf();
	{
		UCHAR id_header[4];
		Zero(id_header, sizeof(id_header));
		id_header[0] = *idr_type;
		WriteBuf(idr_body, id_header, sizeof(id_header));
		WriteBuf(idr_body, addr, addr_size);
	}

	return idr_body;
}

// Create both directions of the first Child SA. On success the SAs are
// inserted into the server lists and paired.
static bool IkeV2CreateChildSaPairEx(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *sa,
									 IKE_PACKET_PAYLOAD *sa_payload, IPSEC_SA_TRANSFORM_SETTING *child_setting,
									 UINT *our_spi, IPSECSA **sa_c_out, IPSECSA **sa_s_out,
									 BUF *initiator_rand, BUF *responder_rand)
{
	UINT client_spi = 0;
	UCHAR zero_iv[IKE_MAX_BLOCK_SIZE];
	IPSECSA *sa_c = NULL, *sa_s = NULL;
	// Validate arguments
	if (ike == NULL || c == NULL || sa == NULL || sa_payload == NULL || child_setting == NULL ||
		our_spi == NULL || sa_c_out == NULL || sa_s_out == NULL ||
		initiator_rand == NULL || responder_rand == NULL)
	{
		return false;
	}

	Zero(child_setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

	if (IkeV2SelectChildSaProposal(ike, sa_payload, child_setting, &client_spi) == false)
	{
		return false;
	}

	// The capsule mode follows the NAT detection result
	if (sa->V2UseTransportMode)
	{
		child_setting->CapsuleMode = sa->V2NatDetected ? IKE_P2_CAPSULE_NAT_TRANSPORT_1 : IKE_P2_CAPSULE_TRANSPORT;
	}
	else
	{
		child_setting->CapsuleMode = sa->V2NatDetected ? IKE_P2_CAPSULE_NAT_TUNNEL_1 : IKE_P2_CAPSULE_TUNNEL;
	}

	*our_spi = GenerateNewIPsecSaSpi(ike, client_spi);

	// Child SA key material: prf+ (SK_d, Ni | Nr).
	// Layout: all the initiator keys first, then all the responder keys,
	// each block being the encryption key followed by the integrity key
	{
		UINT enc_key_size = child_setting->CryptoKeySize;
		UINT integ_key_size = child_setting->Hash->HashSize;
		UINT keymat_size = 2 * (enc_key_size + integ_key_size);
		BUF *keymat = IkeV2CalcChildSaKeymatEx(ike, sa, initiator_rand, responder_rand, keymat_size);

		if (keymat == NULL)
		{
			return false;
		}

		Zero(zero_iv, sizeof(zero_iv));

		sa_c = NewIPsecSa(ike, c, sa, false, 1, false, zero_iv, *our_spi,
			initiator_rand->Buf, initiator_rand->Size,
			responder_rand->Buf, responder_rand->Size, child_setting, NULL, 0);

		sa_s = NewIPsecSa(ike, c, sa, false, 1, true, zero_iv, client_spi,
			initiator_rand->Buf, initiator_rand->Size,
			responder_rand->Buf, responder_rand->Size, child_setting, NULL, 0);

		if (sa_c == NULL || sa_s == NULL)
		{
			FreeBuf(keymat);
			return false;
		}

		// Overwrite the IKEv1 key material with the IKEv2 derived keys:
		// the inbound SA (client -> server) uses the initiator keys,
		// the outbound SA (server -> client) uses the responder keys
		{
			UCHAR *km = (UCHAR *)keymat->Buf;
			UCHAR *key_i = km;
			UCHAR *key_r = km + enc_key_size + integ_key_size;

			if (sa_c->CryptoKey != NULL)
			{
				IkeFreeKey(sa_c->CryptoKey);
			}
			sa_c->CryptoKey = IkeNewKey(child_setting->Crypto, key_i, enc_key_size);
			Copy(sa_c->KeyMat, key_i, enc_key_size);
			Copy(sa_c->HashKey, key_i + enc_key_size, integ_key_size);

			if (sa_s->CryptoKey != NULL)
			{
				IkeFreeKey(sa_s->CryptoKey);
			}
			sa_s->CryptoKey = IkeNewKey(child_setting->Crypto, key_r, enc_key_size);
			Copy(sa_s->KeyMat, key_r, enc_key_size);
			Copy(sa_s->HashKey, key_r + enc_key_size, integ_key_size);
		}

		FreeBuf(keymat);
	}

	sa_c->PairIPsecSa = sa_s;
	sa_s->PairIPsecSa = sa_c;

	Insert(ike->IPsecSaList, sa_c);
	Insert(ike->IPsecSaList, sa_s);

	*sa_c_out = sa_c;
	*sa_s_out = sa_s;

	return true;
}

static bool IkeV2CreateChildSaPair(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *sa,
									IKE_PACKET_PAYLOAD *sa_payload, IPSEC_SA_TRANSFORM_SETTING *child_setting,
									UINT *our_spi, IPSECSA **sa_c_out, IPSECSA **sa_s_out)
{
	return IkeV2CreateChildSaPairEx(ike, c, sa, sa_payload, child_setting, our_spi,
		sa_c_out, sa_s_out, sa->InitiatorRand, sa->ResponderRand);
}

// Append the SAr2 and the narrowed traffic selectors to the response payload
// list. The responder echoes the first selector of each direction, except
// that when a virtual IP address was assigned and the initiator's selector
// covers it, the initiator side is narrowed to exactly that address
// (RFC 7296 section 2.9 traffic selector narrowing, as expected by
// strongSwan and Apple clients).
static bool IkeV2AddChildSaResponsePayloadsEx(IKE_SERVER *ike, LIST *payload_list,
											  IPSEC_SA_TRANSFORM_SETTING *child_setting, UINT our_spi,
											  IKE_PACKET_PAYLOAD *tsi_payload, IKE_PACKET_PAYLOAD *tsr_payload,
											  IP *narrow_ip)
{
	IKEV2_PACKET_TS_PAYLOAD *tsi, *tsr;
	IKEV2_TS *first_i;
	// Validate arguments
	if (ike == NULL || payload_list == NULL || child_setting == NULL || tsi_payload == NULL || tsr_payload == NULL)
	{
		return false;
	}

	tsi = &tsi_payload->Payload.TsV2;
	tsr = &tsr_payload->Payload.TsV2;

	if (LIST_NUM(tsi->TsList) < 1 || LIST_NUM(tsr->TsList) < 1)
	{
		return false;
	}

	Add(payload_list, IkeV2BuildChildSaResponseProposal(ike, child_setting, our_spi));

	{
		IKEV2_TS *echo_i = ZeroMalloc(sizeof(IKEV2_TS));
		IKEV2_TS *echo_r = ZeroMalloc(sizeof(IKEV2_TS));
		UINT i;

		// Select the first IPv4 selector of the initiator: the peer may
		// propose an IPv6 selector first (when it also requested an IPv6
		// virtual address)
		first_i = NULL;
		for (i = 0; i < LIST_NUM(tsi->TsList); i++)
		{
			IKEV2_TS *ts = (IKEV2_TS *)LIST_DATA(tsi->TsList, i);

			if (ts->Type == IKEV2_TS_IPV4_ADDR_RANGE)
			{
				first_i = ts;
				break;
			}
		}

		Copy(echo_r, LIST_DATA(tsr->TsList, 0), sizeof(IKEV2_TS));

		if (narrow_ip != NULL && IsZeroIP(narrow_ip) == false)
		{
			// An IPv4 virtual address was assigned: narrow the initiator
			// side to exactly that address. The "dynamic" selector some
			// peers propose (an IPv6 any range while requesting both
			// families) conceptually covers whatever address gets assigned,
			// so narrowing applies even without an IPv4 selector in the
			// proposal.
			bool covered = true;

			if (first_i != NULL)
			{
				covered = (CmpIpAddr(&first_i->StartAddress, narrow_ip) <= 0 &&
					CmpIpAddr(narrow_ip, &first_i->EndAddress) <= 0);
			}

			if (covered)
			{
				Zero(echo_i, sizeof(IKEV2_TS));
				echo_i->Type = IKEV2_TS_IPV4_ADDR_RANGE;
				echo_i->IpProtocol = first_i != NULL ? first_i->IpProtocol : 0;
				echo_i->StartPort = 0;
				echo_i->EndPort = 65535;
				Copy(&echo_i->StartAddress, narrow_ip, sizeof(IP));
				Copy(&echo_i->EndAddress, narrow_ip, sizeof(IP));

				first_i = NULL;	// echo_i already built
			}
		}

		if (first_i != NULL)
		{
			Copy(echo_i, first_i, sizeof(IKEV2_TS));
		}

		Add(payload_list, IkeV2NewTsPayload(IKEV2_PAYLOAD_TS_INITIATOR, NewListSingle(echo_i)));
		Add(payload_list, IkeV2NewTsPayload(IKEV2_PAYLOAD_TS_RESPONDER, NewListSingle(echo_r)));
	}

	return true;
}

static bool IkeV2AddChildSaResponsePayloads(IKE_SERVER *ike, LIST *payload_list,
											IPSEC_SA_TRANSFORM_SETTING *child_setting, UINT our_spi,
											IKE_PACKET_PAYLOAD *tsi_payload, IKE_PACKET_PAYLOAD *tsr_payload)
{
	return IkeV2AddChildSaResponsePayloadsEx(ike, payload_list, child_setting, our_spi,
		tsi_payload, tsr_payload, NULL);
}

//// IKE_AUTH

static bool IkeV2AddChildSaResponsePayloadsEx(IKE_SERVER *ike, LIST *payload_list,
											  IPSEC_SA_TRANSFORM_SETTING *child_setting, UINT our_spi,
											  IKE_PACKET_PAYLOAD *tsi_payload, IKE_PACKET_PAYLOAD *tsr_payload,
											  IP *narrow_ip);

static bool IkeV2CreateChildSaPairEx(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *sa,
									 IKE_PACKET_PAYLOAD *sa_payload, IPSEC_SA_TRANSFORM_SETTING *child_setting,
									 UINT *our_spi, IPSECSA **sa_c_out, IPSECSA **sa_s_out,
									 BUF *initiator_rand, BUF *responder_rand);

// Message ID gate shared by all IKEv2 request handlers.
// Returns true when the request should be processed. A retransmission of
// the previous request is answered from the cached response. When the peer
// skipped ahead (it gave up waiting for a lost response of ours and started
// a new exchange) the expected counter catches up within a bounded window,
// otherwise the two sides would deadlock silently forever.
static bool IkeV2CheckMessageId(IKE_SERVER *ike, IKE_SA *sa, IKE_PACKET *header)
{
	// Validate arguments
	if (ike == NULL || sa == NULL || header == NULL)
	{
		return false;
	}

	if (header->MessageId == sa->V2MsgIdRecvExpected)
	{
		return true;
	}

	if (header->MessageId == sa->V2MsgIdRecvExpected - 1 && sa->SendBuffer != NULL)
	{
		// Retransmission of the previous request: resend the cached response
		IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &sa->IkeClient->ServerIP, sa->IkeClient->ServerPort,
			&sa->IkeClient->ClientIP, sa->IkeClient->ClientPort,
			Clone(sa->SendBuffer->Buf, sa->SendBuffer->Size), sa->SendBuffer->Size);
		sa->LastCommTick = ike->Now;
		return false;
	}

	if (header->MessageId > sa->V2MsgIdRecvExpected &&
		header->MessageId - sa->V2MsgIdRecvExpected <= 8)
	{
		// The peer skipped one or more exchanges: catch up so that the
		// increment after processing lands on the right next value
		sa->V2MsgIdRecvExpected = header->MessageId;
		return true;
	}

	return false;
}

// Forward declarations of the IKE_AUTH sub handlers
static void IkeV2ProcIkeAuthFirst(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa);
static void IkeV2ProcIkeAuthEapRound(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa);
static void IkeV2EapMschapV2Response(IKE_SERVER *ike, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa, BUF *type_data);
static void IkeV2EapFinalRound(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa,
							   IKE_PACKET_PAYLOAD *auth_payload);

// Process an IKE_AUTH request: dispatches to the first round handler or,
// while the EAP exchange is running, to the EAP round handler
void IkeV2ProcIkeAuth(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa)
{
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL || sa == NULL)
	{
		return;
	}

	if (sa->V2State != IKEV2_STATE_SA_INIT_SENT && sa->V2State != IKEV2_STATE_IKE_AUTH_EAP)
	{
		return;
	}

	if (IkeV2CheckMessageId(ike, sa, header) == false)
	{
		return;
	}

	// Decrypt and parse the SK payload
	if (IkeV2RecvEncrypted(ike, sa, p, header) == false)
	{
		return;
	}

	sa->V2MsgIdRecvExpected++;
	sa->LastCommTick = ike->Now;

	if (sa->V2State == IKEV2_STATE_SA_INIT_SENT)
	{
		IkeV2ProcIkeAuthFirst(ike, p, header, c, sa);
	}
	else
	{
		IkeV2ProcIkeAuthEapRound(ike, p, header, c, sa);
	}
}

// Handle the first IKE_AUTH request: either the initiator authenticated
// itself with the AUTH payload (pre-shared key mode) or it asks for EAP
static void IkeV2ProcIkeAuthFirst(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa)
{
	IKE_PACKET_PAYLOAD *sa_payload, *idi_payload, *auth_payload, *tsi_payload, *tsr_payload;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL || sa == NULL)
	{
		return;
	}

	sa_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_SA, 0);
	idi_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_ID_INITIATOR, 0);
	auth_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_AUTH, 0);
	tsi_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_TS_INITIATOR, 0);
	tsr_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_TS_RESPONDER, 0);

	if (sa_payload == NULL || idi_payload == NULL || tsi_payload == NULL || tsr_payload == NULL)
	{
		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
			IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	// Keep the raw IDi payload body: it feeds the AUTH verification
	if (sa->V2IdiBody != NULL)
	{
		FreeBuf(sa->V2IdiBody);
	}
	sa->V2IdiBody = CloneBuf(idi_payload->BitArray);
	sa->V2IdiType = idi_payload->Payload.Id.Type;

	// The USE_TRANSPORT_MODE notify only appears in the first IKE_AUTH request
	sa->V2UseTransportMode = (IkeV2GetNotifyPayload(header, IKEV2_NOTIFY_USE_TRANSPORT_MODE, 0) != NULL) ? true : false;

	if (auth_payload != NULL)
	{
		// Pre-shared key mode
		IPSEC_SA_TRANSFORM_SETTING child_setting;
		UINT our_spi = 0;
		IPSECSA *sa_c = NULL, *sa_s = NULL;
		LIST *payload_list;
		BUF *idr_body = NULL;
		UCHAR idr_type;
		IKE_PACKET_PAYLOAD *auth_out;

		if (IkeV2VerifyInitiatorAuthSecret(ike, sa, auth_payload, ike->Secret, StrLen(ike->Secret)) == false)
		{
			IPsecLog(ike, c, sa, NULL, "LI2_AUTH_FAILED");

			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
				IKEV2_NOTIFY_AUTHENTICATION_FAILED, NULL, 0);

			IkeV2MarkIkeSaDeleted(ike, sa);
			return;
		}

		StrCpy(c->ClientId, sizeof(c->ClientId), idi_payload->Payload.Id.StrData);
		StrCpy(sa->Secret, sizeof(sa->Secret), ike->Secret);

		if (IkeV2CreateChildSaPair(ike, c, sa, sa_payload, &child_setting, &our_spi, &sa_c, &sa_s) == false)
		{
			IPsecLog(ike, c, sa, NULL, "LI_IPSEC_NO_TRANSFORM");

			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
				IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, NULL, 0);

			IkeV2MarkIkeSaDeleted(ike, sa);
			return;
		}

		idr_body = IkeV2BuildIdrBody(ike, c, &idr_type);

		payload_list = NewListFast(NULL);

		Add(payload_list, IkeV2NewIdPayload(IKEV2_PAYLOAD_ID_RESPONDER, idr_type,
			((UCHAR *)idr_body->Buf) + 4, idr_body->Size - 4));

		auth_out = IkeV2BuildAuthSecret(ike, sa, ike->Secret, StrLen(ike->Secret),
			sa->V2SaInitResponseData, sa->InitiatorRand,
			sa->V2SkPr, sa->TransformSetting.V2Prf->HashSize, idr_body);

		if (auth_out != NULL)
		{
			// Payload order: IDr, AUTH, SAr2, TSi, TSr
			Add(payload_list, auth_out);
		}

		if (auth_out == NULL || IkeV2AddChildSaResponsePayloads(ike, payload_list, &child_setting,
			our_spi, tsi_payload, tsr_payload) == false)
		{
			IkeFreePayloadList(payload_list);
			FreeBuf(idr_body);
			IkeV2MarkIkeSaDeleted(ike, sa);
			return;
		}

		IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);

		FreeBuf(idr_body);

		// State transition
		sa->Established = true;
		sa->EstablishedTick = ike->Now;
		sa->V2State = IKEV2_STATE_ESTABLISHED;

		sa_c->Established = true;
		sa_s->Established = true;

		c->CurrentIkeSa = sa;
		c->CurrentIpSecSaRecv = sa_c;
		c->CurrentIpSecSaSend = sa_s;

		IPsecLog(ike, c, sa, sa_c, "LI2_IKE_SA_ESTABLISHED",
			sa->InitiatorCookie, sa->ResponderCookie, c->ClientId,
			sa->V2UseTransportMode ? _UU("L_YES") : _UU("L_NO"),
			sa->V2NatDetected ? _UU("L_YES") : _UU("L_NO"),
			child_setting.Crypto->Name, child_setting.CryptoKeySize * 8, child_setting.Hash->Name);
	}
	else
	{
		// The initiator asks for EAP authentication (RFC 7296 section 2.16)
		LIST *payload_list;
		BUF *idr_body = NULL;
		UCHAR idr_type;
		IKE_PACKET_PAYLOAD *auth_out;

		StrCpy(c->ClientId, sizeof(c->ClientId), idi_payload->Payload.Id.StrData);
		StrCpy(sa->V2EapUsername, sizeof(sa->V2EapUsername), idi_payload->Payload.Id.StrData);

		// Remember the Child SA proposal and the traffic selectors: they are
		// needed when the exchange completes several rounds later
		if (sa->V2ChildSaBody != NULL)
		{
			FreeBuf(sa->V2ChildSaBody);
		}
		sa->V2ChildSaBody = CloneBuf(sa_payload->BitArray);
		if (sa->V2TsiBody != NULL)
		{
			FreeBuf(sa->V2TsiBody);
		}
		sa->V2TsiBody = CloneBuf(tsi_payload->BitArray);
		if (sa->V2TsrBody != NULL)
		{
			FreeBuf(sa->V2TsrBody);
		}
		sa->V2TsrBody = CloneBuf(tsr_payload->BitArray);

		sa->V2EapMode = true;
		sa->V2State = IKEV2_STATE_IKE_AUTH_EAP;
		sa->V2EapLastSentId = (UCHAR)(Rand32() % 250 + 1);

		// First EAP response: IDr, our AUTH (shared key), EAP-Request/Identity
		payload_list = NewListFast(NULL);

		idr_body = IkeV2BuildIdrBody(ike, c, &idr_type);

		// Server authentication method: when the peer explicitly requested
		// our certificate (CERTREQ in the first IKE_AUTH request) and a
		// server certificate is configured, use the digital signature method
		// together with the CERT payload (expected by Apple and Windows in
		// EAP mode); otherwise the shared key method. The SIGNATURE_HASH_
		// ALGORITHMS notify alone is NOT a usable indicator: strongSwan
		// announces it unconditionally regardless of the configured auth.
		if (IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_CERTREQ, 0) != NULL)
		{
			X *server_x = NULL;

			Lock(ike->Cedar->lock);
			{
				if (ike->Cedar->ServerX != NULL)
				{
					server_x = CloneX(ike->Cedar->ServerX);
				}
			}
			Unlock(ike->Cedar->lock);

			if (server_x != NULL)
			{
				// The signature AUTH covers the IDr payload, so replace the
				// address based IDr with the certificate identity (its CN)
				// BEFORE building the AUTH payload: peers match the received
				// IDr against the certificate subject and their configured
				// remote identity
				if (server_x->subject_name != NULL && UniStrLen(server_x->subject_name->CommonName) > 0)
				{
					char cn[MAX_SIZE];

					UniToStr(cn, sizeof(cn), server_x->subject_name->CommonName);

					idr_body = NewBuf();
					{
						UCHAR id_header[4];
						Zero(id_header, sizeof(id_header));
						id_header[0] = IKE_ID_FQDN;
						WriteBuf(idr_body, id_header, sizeof(id_header));
						WriteBuf(idr_body, cn, StrLen(cn));
					}

					idr_type = IKE_ID_FQDN;
				}
			}

			auth_out = IkeV2BuildSignatureAuth(ike, sa, sa->V2SaInitResponseData, sa->InitiatorRand,
				sa->V2SkPr, sa->TransformSetting.V2Prf->HashSize, idr_body, true);

			if (auth_out != NULL && server_x != NULL)
			{
				// Send the certificate right before the AUTH payload
				BUF *der = XToBuf(server_x, false);

				if (der != NULL)
				{
					IKE_PACKET_PAYLOAD *cert_payload = IkeNewPayload(IKEV2_PAYLOAD_CERT);

					cert_payload->Payload.Cert.CertType = IKE_CERT_TYPE_X509;
					cert_payload->Payload.Cert.CertData = CloneBuf(der);

					Add(payload_list, cert_payload);

					FreeBuf(der);
				}
			}

			if (server_x != NULL)
			{
				FreeX(server_x);
			}
		}
		else
		{
			auth_out = NULL;
		}

		if (auth_out == NULL)
		{
			// Fall back to the pre-shared key method with the address IDr
			FreeBuf(idr_body);
			idr_body = IkeV2BuildIdrBody(ike, c, &idr_type);

			auth_out = IkeV2BuildAuthSecret(ike, sa, ike->Secret, StrLen(ike->Secret),
				sa->V2SaInitResponseData, sa->InitiatorRand,
				sa->V2SkPr, sa->TransformSetting.V2Prf->HashSize, idr_body);
		}

		if (idr_body == NULL || auth_out == NULL)
		{
			IkeFreePayloadList(payload_list);
			FreeBuf(idr_body);
			IkeV2MarkIkeSaDeleted(ike, sa);
			return;
		}

		Add(payload_list, IkeV2NewIdPayload(IKEV2_PAYLOAD_ID_RESPONDER, idr_type,
			((UCHAR *)idr_body->Buf) + 4, idr_body->Size - 4));

		// The final AUTH of the EAP exchange signs exactly this IDr payload:
		// keep it for IkeV2EapFinalRound
		if (sa->V2IdrBody != NULL)
		{
			FreeBuf(sa->V2IdrBody);
		}
		sa->V2IdrBody = CloneBuf(idr_body);

		FreeBuf(idr_body);

		Add(payload_list, auth_out);

		Add(payload_list, IkeV2NewEapPayload(IKEV2_EAP_CODE_REQUEST, sa->V2EapLastSentId,
			IKEV2_EAP_TYPE_IDENTITY, NULL, 0));

		IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);

		IPsecLog(ike, c, sa, NULL, "LI2_EAP_STARTED", c->ClientId);
	}
}

// Handle an IKE_AUTH round while the EAP exchange is running, including the
// final request that carries the AUTH payload computed with the EAP MSK
static void IkeV2ProcIkeAuthEapRound(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa)
{
	IKE_PACKET_PAYLOAD *auth_payload, *eap_payload;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL || sa == NULL)
	{
		return;
	}

	auth_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_AUTH, 0);
	eap_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_EAP, 0);

	if (auth_payload != NULL)
	{
		// Final round: the initiator proves possession of the EAP MSK
		IkeV2EapFinalRound(ike, p, header, c, sa, auth_payload);
		return;
	}

	if (eap_payload == NULL)
	{
		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
			IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	// Parse the EAP message
	{
		UCHAR code, id, type;
		BUF *type_data = NULL;

		if (IkeV2ParseEapMessage(eap_payload->Payload.GeneralData.Data, &code, &id, &type, &type_data) == false)
		{
			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
				IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);

			IkeV2MarkIkeSaDeleted(ike, sa);
			return;
		}

		if (code != IKEV2_EAP_CODE_RESPONSE)
		{
			FreeBuf(type_data);
			return;
		}

		if (type == IKEV2_EAP_TYPE_IDENTITY)
		{
			// Identity response: start the MSCHAPv2 challenge
			char identity[MAX_SIZE];
			UINT identity_len;

			Zero(identity, sizeof(identity));

			if (type_data != NULL && type_data->Size > 0)
			{
				identity_len = MIN(type_data->Size, sizeof(identity) - 1);
				Copy(identity, type_data->Buf, identity_len);
				identity[identity_len] = 0;
			}

			if (IsEmptyStr(identity) == false)
			{
				StrCpy(sa->V2EapUsername, sizeof(sa->V2EapUsername), identity);
			}

			Rand(sa->V2MsChapV2ServerChallenge, IKEV2_MSCHAPV2_CHALLENGE_SIZE);

			sa->V2EapLastSentId++;

			{
				LIST *payload_list = NewListSingle(IkeV2NewEapMschapV2Challenge(
					sa->V2EapLastSentId, sa->V2EapLastSentId,
					sa->V2MsChapV2ServerChallenge, "SoftEther VPN"));

				IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);
			}

			FreeBuf(type_data);
		}
		else if (type == IKEV2_EAP_TYPE_MSCHAPV2)
		{
			if (type_data != NULL && type_data->Size >= 1)
			{
				UCHAR opcode = ((UCHAR *)type_data->Buf)[0];

				if (opcode == 2)
				{
					// MSCHAPv2 Response
					IkeV2EapMschapV2Response(ike, header, c, sa, type_data);
					type_data = NULL;	// Ownership taken over
				}
				else if (opcode == 3)
				{
					// MSCHAPv2 Success acknowledgement: finish with EAP-Success
					if (sa->V2MsChapV2SuccessSent && sa->V2MskSize != 0)
					{
						LIST *payload_list = NewListSingle(IkeV2NewEapPayload(IKEV2_EAP_CODE_SUCCESS,
							sa->V2EapLastSentId, 0, NULL, 0));

						IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);
					}

					FreeBuf(type_data);
					type_data = NULL;
				}
				else
				{
					FreeBuf(type_data);
					type_data = NULL;
					IkeV2MarkIkeSaDeleted(ike, sa);
				}
			}

			if (type_data != NULL)
			{
				FreeBuf(type_data);
			}
		}
		else if (type == IKEV2_EAP_TYPE_NAK)
		{
			// NAK in response to our EAP-Request/Identity: the peer lists
			// the methods it supports. strongSwan answers the identity
			// request with a NAK naming its configured method instead of an
			// EAP-Response/Identity, so start MSCHAPv2 when it is offered
			bool mschapv2_preferred = false;

			if (type_data != NULL)
			{
				UINT i;
				for (i = 0; i < type_data->Size; i++)
				{
					if (((UCHAR *)type_data->Buf)[i] == IKEV2_EAP_TYPE_MSCHAPV2)
					{
						mschapv2_preferred = true;
						break;
					}
				}
			}

			FreeBuf(type_data);
			type_data = NULL;

			if (mschapv2_preferred)
			{
				// Proceed with the MSCHAPv2 challenge
				Rand(sa->V2MsChapV2ServerChallenge, IKEV2_MSCHAPV2_CHALLENGE_SIZE);

				sa->V2EapLastSentId++;

				{
					LIST *payload_list = NewListSingle(IkeV2NewEapMschapV2Challenge(
						sa->V2EapLastSentId, sa->V2EapLastSentId,
						sa->V2MsChapV2ServerChallenge, "SoftEther VPN"));

					IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);
				}
			}
			else
			{
				LIST *payload_list = NewListSingle(IkeV2NewEapPayload(IKEV2_EAP_CODE_FAILURE,
					sa->V2EapLastSentId, 0, NULL, 0));

				IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);

				IPsecLog(ike, c, sa, NULL, "LI2_EAP_UNSUPPORTED");

				IkeV2MarkIkeSaDeleted(ike, sa);
			}
		}
		else
		{
			FreeBuf(type_data);
			IkeV2MarkIkeSaDeleted(ike, sa);
		}
	}
}

// Verify an MSCHAPv2 response, derive the MSK and start the hub session
static void IkeV2EapMschapV2Response(IKE_SERVER *ike, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa, BUF *type_data)
{
	UCHAR peer_challenge[IKEV2_MSCHAPV2_CHALLENGE_SIZE];
	UCHAR nt_response[IKEV2_MSCHAPV2_NT_RESPONSE_SIZE];
	char name[MAX_SIZE];
	UCHAR nt_hash_hash[MD5_SIZE];
	UCHAR server_response_20[IKEV2_MSCHAPV2_S_RESPONSE_SIZE];
	// Validate arguments
	if (ike == NULL || header == NULL || c == NULL || sa == NULL || type_data == NULL)
	{
		return;
	}

	if (sa->V2MskSize != 0)
	{
		// A response was already processed: ignore duplicates
		return;
	}

	Zero(name, sizeof(name));

	if (IkeV2ParseEapMschapV2Response(type_data, peer_challenge, nt_response, name, sizeof(name)) == false)
	{
		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	if (IsEmptyStr(name))
	{
		StrCpy(name, sizeof(name), sa->V2EapUsername);
	}

	StrCpy(sa->V2EapUsername, sizeof(sa->V2EapUsername), name);

	if (IkeV2MsChapV2VerifyHubUser(ike, name, sa->V2MsChapV2ServerChallenge, peer_challenge, nt_response,
		nt_hash_hash, server_response_20) == false)
	{
		IPsecLog(ike, c, sa, NULL, "LI2_AUTH_FAILED");

		{
			LIST *payload_list = NewListSingle(IkeV2NewEapPayload(IKEV2_EAP_CODE_FAILURE,
				sa->V2EapLastSentId, 0, NULL, 0));

			IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);
		}

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	// Derive the MSK and remember it for the final AUTH exchange
	IkeV2CalcMskFromMsChapV2(nt_hash_hash, nt_response, sa->V2Msk);
	sa->V2MskSize = IKEV2_MSK_SIZE;

	// Start the hub session in the background: the IPC login re-verifies the
	// MSCHAPv2 data and the DHCP request obtains the virtual IP address
	if (c->V2IpcAsync == NULL)
	{
		c->V2IpcAsync = IkeV2NewIpcAsync(ike, c, name,
			sa->V2MsChapV2ServerChallenge, peer_challenge, nt_response);
	}

	sa->V2MsChapV2SuccessSent = true;
	sa->V2EapLastSentId++;

	{
		LIST *payload_list = NewListSingle(IkeV2NewEapMschapV2Success(
			sa->V2EapLastSentId, sa->V2EapLastSentId, server_response_20));

		IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);
	}
}

// Final round of the EAP exchange: verify the AUTH computed with the MSK,
// finish the Child SA creation and reply with the virtual IP configuration
static void IkeV2EapFinalRound(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa,
							   IKE_PACKET_PAYLOAD *auth_payload)
{
	IKE_PACKET_PAYLOAD *sa_payload, *tsi_payload, *tsr_payload;
	IPSEC_SA_TRANSFORM_SETTING child_setting;
	UINT our_spi = 0;
	IPSECSA *sa_c = NULL, *sa_s = NULL;
	IPC *ipc;
	LIST *payload_list;
	BUF *idr_body = NULL;
	UCHAR idr_type;
	IKE_PACKET_PAYLOAD *auth_out, *cp_payload;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL || sa == NULL || auth_payload == NULL)
	{
		return;
	}

	if (sa->V2MskSize == 0)
	{
		// EAP was not completed
		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
			IKEV2_NOTIFY_AUTHENTICATION_FAILED, NULL, 0);

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	if (IkeV2VerifyInitiatorAuthSecret(ike, sa, auth_payload, sa->V2Msk, sa->V2MskSize) == false)
	{
		IPsecLog(ike, c, sa, NULL, "LI2_AUTH_FAILED");

		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
			IKEV2_NOTIFY_AUTHENTICATION_FAILED, NULL, 0);

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	// Wait for the hub session (login + DHCP) to become ready
	ipc = IkeV2WaitIpcReady(c);

	if (ipc == NULL)
	{
		IPsecLog(ike, c, sa, NULL, "LI2_IPC_FAILED", sa->V2EapUsername);

		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
			IKEV2_NOTIFY_AUTHENTICATION_FAILED, NULL, 0);

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	c->V2Ipc = ipc;
	IPCSetSockEventWhenRecvL2Packet(ipc, ike->SockEvent);

	// Open the L3 protocol of the IPC virtual host: without this the IPC
	// discards every received IPv4 packet instead of queueing it for
	// IPCRecvIPv4 (the WireGuard module sets the same flag)
	IPC_PROTO_SET_STATUS(ipc, IPv4State, IPC_PROTO_STATUS_OPENED);

	// Re-parse the stored Child SA proposal and traffic selectors
	sa_payload = IkeParsePayload(IKEV2_PAYLOAD_SA, sa->V2ChildSaBody);
	tsi_payload = IkeParsePayload(IKEV2_PAYLOAD_TS_INITIATOR, sa->V2TsiBody);
	tsr_payload = IkeParsePayload(IKEV2_PAYLOAD_TS_RESPONDER, sa->V2TsrBody);

	if (sa_payload == NULL || tsi_payload == NULL || tsr_payload == NULL ||
		IkeV2CreateChildSaPair(ike, c, sa, sa_payload, &child_setting, &our_spi, &sa_c, &sa_s) == false)
	{
		IPsecLog(ike, c, sa, NULL, "LI_IPSEC_NO_TRANSFORM");

		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId,
			IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, NULL, 0);

		if (sa_payload != NULL)
		{
			IkeFreePayload(sa_payload);
		}
		if (tsi_payload != NULL)
		{
			IkeFreePayload(tsi_payload);
		}
		if (tsr_payload != NULL)
		{
			IkeFreePayload(tsr_payload);
		}

		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	// Build the final response: AUTH(MSK), CP, SAr2, TSi, TSr.
	// The AUTH signs the IDr of the FIRST IKE_AUTH response: the peer
	// verifies it against exactly that payload (RFC 7296 section 2.16)
	if (sa->V2IdrBody != NULL)
	{
		idr_body = CloneBuf(sa->V2IdrBody);
	}
	else
	{
		idr_body = IkeV2BuildIdrBody(ike, c, &idr_type);
	}

	payload_list = NewListFast(NULL);

	auth_out = IkeV2BuildAuthSecret(ike, sa, sa->V2Msk, sa->V2MskSize,
		sa->V2SaInitResponseData, sa->InitiatorRand,
		sa->V2SkPr, sa->TransformSetting.V2Prf->HashSize, idr_body);

	FreeBuf(idr_body);

	if (auth_out == NULL)
	{
		IkeFreePayloadList(payload_list);
		IkeFreePayload(sa_payload);
		IkeFreePayload(tsi_payload);
		IkeFreePayload(tsr_payload);
		IkeV2MarkIkeSaDeleted(ike, sa);
		return;
	}

	Add(payload_list, auth_out);

	cp_payload = IkeV2NewCpReplyPayload(c->V2IpcAsync);
	if (cp_payload != NULL)
	{
		Add(payload_list, cp_payload);
	}

	{
		IP narrow_ip;

		Zero(&narrow_ip, sizeof(narrow_ip));
		UINTToIP(&narrow_ip, c->V2IpcAsync->L3ClientAddressOption.ClientAddress);

		if (IkeV2AddChildSaResponsePayloadsEx(ike, payload_list, &child_setting, our_spi,
			tsi_payload, tsr_payload, &narrow_ip) == false)
		{
			IkeFreePayloadList(payload_list);
			IkeFreePayload(sa_payload);
			IkeFreePayload(tsi_payload);
			IkeFreePayload(tsr_payload);
			IkeV2MarkIkeSaDeleted(ike, sa);
			return;
		}
	}

	IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_IKE_AUTH, header->MessageId, payload_list);

	IkeFreePayload(sa_payload);
	IkeFreePayload(tsi_payload);
	IkeFreePayload(tsr_payload);

	// State transition
	sa->Established = true;
	sa->EstablishedTick = ike->Now;
	sa->V2State = IKEV2_STATE_ESTABLISHED;

	sa_c->Established = true;
	sa_s->Established = true;

	c->CurrentIkeSa = sa;
	c->CurrentIpSecSaRecv = sa_c;
	c->CurrentIpSecSaSend = sa_s;

	{
		char ip_str[64];
		IP vip;

		Zero(&vip, sizeof(vip));
		UINTToIP(&vip, c->V2IpcAsync->L3ClientAddressOption.ClientAddress);
		IPToStr(ip_str, sizeof(ip_str), &vip);

		IPsecLog(ike, c, sa, sa_c, "LI2_IKE_SA_ESTABLISHED",
			sa->InitiatorCookie, sa->ResponderCookie, sa->V2EapUsername,
			sa->V2UseTransportMode ? _UU("L_YES") : _UU("L_NO"),
			sa->V2NatDetected ? _UU("L_YES") : _UU("L_NO"),
			child_setting.Crypto->Name, child_setting.CryptoKeySize * 8, child_setting.Hash->Name);

		IPsecLog(ike, c, sa, NULL, "LI2_IPC_CONNECTED", ip_str);
	}
}

//// INFORMATIONAL

// Process an INFORMATIONAL request (DPD, DELETE, unknown notifies)
void IkeV2ProcInformational(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa)
{
	IKE_PACKET_PAYLOAD *delete_payload;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL || sa == NULL)
	{
		return;
	}

	if (sa->V2State != IKEV2_STATE_ESTABLISHED)
	{
		return;
	}

	if (IkeV2CheckMessageId(ike, sa, header) == false)
	{
		return;
	}

	if (IkeV2RecvEncrypted(ike, sa, p, header) == false)
	{
		return;
	}

	sa->V2MsgIdRecvExpected++;
	sa->LastCommTick = ike->Now;

	// DELETE payload processing
	delete_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_DELETE, 0);

	if (delete_payload != NULL)
	{
		IKE_PACKET_DELETE_PAYLOAD *d = &delete_payload->Payload.Delete;

		if (d->ProtocolId == IKE_PROTOCOL_ID_IKE)
		{
			// Delete of the IKE SA itself: answer with an empty response and
			// tear down the whole client
			IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_INFORMATIONAL, header->MessageId, NewListFast(NULL));

			IPsecLog(ike, c, sa, NULL, "LI2_DELETE_RECEIVED");

			IkeV2MarkIkeClientDeleted(ike, c);

			return;
		}
		else if (d->ProtocolId == IKE_PROTOCOL_ID_IPSEC_ESP)
		{
			// Delete of Child SAs: the received SPIs are the inbound SPIs of
			// the peer, that is our outbound SAs. Respond with our own
			// inbound SPIs and delete both directions of each pair.
			LIST *resp_spi_list = NewListFast(NULL);
			UINT i;

			for (i = 0; i < LIST_NUM(d->SpiList); i++)
			{
				BUF *spi_buf = LIST_DATA(d->SpiList, i);
				UINT spi;
				IPSECSA *sa_out = NULL;
				UINT j;

				if (spi_buf->Size != 4)
				{
					continue;
				}

				spi = (UINT)(((UINT)((UCHAR *)spi_buf->Buf)[0] << 24) | ((UINT)((UCHAR *)spi_buf->Buf)[1] << 16) |
					((UINT)((UCHAR *)spi_buf->Buf)[2] << 8) | (UINT)((UCHAR *)spi_buf->Buf)[3]);

				// Find our outbound SA with this SPI
				for (j = 0; j < LIST_NUM(ike->IPsecSaList); j++)
				{
					IPSECSA *s = LIST_DATA(ike->IPsecSaList, j);

					if (s->IkeClient == c && s->ServerToClient && s->Spi == spi)
					{
						sa_out = s;
						break;
					}
				}

				if (sa_out != NULL)
				{
					IPSECSA *pair = sa_out->PairIPsecSa;

					if (pair != NULL)
					{
						// Remember our inbound SPI for the response
						BUF *resp_spi = NewBuf();
						UCHAR spi_be[4];

						spi_be[0] = (UCHAR)((pair->Spi >> 24) & 0xff);
						spi_be[1] = (UCHAR)((pair->Spi >> 16) & 0xff);
						spi_be[2] = (UCHAR)((pair->Spi >> 8) & 0xff);
						spi_be[3] = (UCHAR)(pair->Spi & 0xff);

						WriteBuf(resp_spi, spi_be, sizeof(spi_be));

						Add(resp_spi_list, resp_spi);
					}

					if (sa_out->Deleting == false)
					{
						sa_out->Deleting = true;

						if (sa_out->SendBuffer != NULL)
						{
							FreeBuf(sa_out->SendBuffer);
							sa_out->SendBuffer = NULL;
						}
					}

					if (pair != NULL && pair->Deleting == false)
					{
						pair->Deleting = true;

						if (pair->SendBuffer != NULL)
						{
							FreeBuf(pair->SendBuffer);
							pair->SendBuffer = NULL;
						}
					}

					ike->StateHasChanged = true;
				}
			}

			if (LIST_NUM(resp_spi_list) >= 1)
			{
				IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_INFORMATIONAL, header->MessageId,
					NewListSingle(IkeV2NewDeletePayload(IKE_PROTOCOL_ID_IPSEC_ESP, resp_spi_list)));
			}
			else
			{
				IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_INFORMATIONAL, header->MessageId, NewListFast(NULL));
				ReleaseList(resp_spi_list);
			}

			return;
		}
	}

	// Everything else (empty request = DPD, unknown notifies) gets an empty
	// response
	IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_INFORMATIONAL, header->MessageId, NewListFast(NULL));
}

//// CREATE_CHILD_SA

// Process a CREATE_CHILD_SA request. Child SA rekeying (RFC 7296
// section 2.8.1) is supported: the peer identifies the old Child SA with a
// REKEY_SA notify and proposes a new SA; the keys are re-derived from SK_d
// and the new nonces without PFS. Requests for additional Child SAs are
// rejected with NO_ADDITIONAL_SAS.
void IkeV2ProcCreateChildSa(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa)
{
	IKE_PACKET_PAYLOAD *rekey_notify, *sa_payload, *nonce_payload, *ke_payload, *tsi_payload, *tsr_payload;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || c == NULL || sa == NULL)
	{
		return;
	}

	if (sa->V2State != IKEV2_STATE_ESTABLISHED)
	{
		return;
	}

	if (IkeV2CheckMessageId(ike, sa, header) == false)
	{
		return;
	}

	if (IkeV2RecvEncrypted(ike, sa, p, header) == false)
	{
		return;
	}

	sa->V2MsgIdRecvExpected++;
	sa->LastCommTick = ike->Now;

	rekey_notify = IkeV2GetNotifyPayload(header, IKEV2_NOTIFY_REKEY_SA, 0);
	sa_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_SA, 0);
	nonce_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_NONCE, 0);
	ke_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_KEY_EXCHANGE, 0);
	tsi_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_TS_INITIATOR, 0);
	tsr_payload = IkeGetPayload(header->PayloadList, IKEV2_PAYLOAD_TS_RESPONDER, 0);

	if (rekey_notify == NULL)
	{
		// A request for an additional Child SA: not supported in this phase
		IPsecLog(ike, c, sa, NULL, "LI2_CREATE_CHILD_SA_REJECTED");

		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
			IKEV2_NOTIFY_NO_ADDITIONAL_SAS, NULL, 0);
		return;
	}

	// Validate the rekey request
	if (sa_payload == NULL || nonce_payload == NULL || tsi_payload == NULL || tsr_payload == NULL)
	{
		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
			IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);
		return;
	}

	// The REKEY_SA notify identifies the old Child SA: ESP protocol and the
	// SPI the peer uses for receiving, which is the SPI of our outbound SA
	{
		IKE_PACKET_NOTICE_PAYLOAD *n = &rekey_notify->Payload.Notice;
		UINT old_spi;
		UINT i;
		bool found = false;

		if (n->ProtocolId != IKE_PROTOCOL_ID_IPSEC_ESP || n->Spi == NULL || n->Spi->Size != 4)
		{
			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
				IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);
			return;
		}

		old_spi = (UINT)(((UINT)((UCHAR *)n->Spi->Buf)[0] << 24) | ((UINT)((UCHAR *)n->Spi->Buf)[1] << 16) |
			((UINT)((UCHAR *)n->Spi->Buf)[2] << 8) | (UINT)((UCHAR *)n->Spi->Buf)[3]);

		for (i = 0; i < LIST_NUM(ike->IPsecSaList); i++)
		{
			IPSECSA *s = LIST_DATA(ike->IPsecSaList, i);

			if (s->IkeClient == c && s->ServerToClient && s->Spi == old_spi)
			{
				found = true;
				break;
			}
		}

		if (found == false)
		{
			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
				IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);
			return;
		}
	}

	// PFS is not supported yet: a KE payload cannot be honoured
	if (ke_payload != NULL)
	{
		IPsecLog(ike, c, sa, NULL, "LI_IPSEC_NO_TRANSFORM");

		IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
			IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, NULL, 0);
		return;
	}

	// Create the new Child SA pair with the new nonces
	{
		IPSEC_SA_TRANSFORM_SETTING child_setting;
		UINT our_spi = 0;
		IPSECSA *sa_c = NULL, *sa_s = NULL;
		BUF *initiator_rand = nonce_payload->Payload.GeneralData.Data;
		BUF *responder_rand = NULL;
		LIST *payload_list;

		if (initiator_rand == NULL || initiator_rand->Size < 16 || initiator_rand->Size > 256)
		{
			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
				IKEV2_NOTIFY_INVALID_SYNTAX, NULL, 0);
			return;
		}

		responder_rand = RandBuf(IKEV2_NONCE_SIZE);

		if (IkeV2CreateChildSaPairEx(ike, c, sa, sa_payload, &child_setting, &our_spi, &sa_c, &sa_s,
			initiator_rand, responder_rand) == false)
		{
			IPsecLog(ike, c, sa, NULL, "LI_IPSEC_NO_TRANSFORM");

			IkeV2SendEncryptedNotify(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId,
				IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, NULL, 0);

			FreeBuf(responder_rand);
			return;
		}

		// Switch the client over to the new pair; the old SAs stay in place
		// until the peer deletes them with an INFORMATIONAL exchange
		c->CurrentIpSecSaRecv = sa_c;
		c->CurrentIpSecSaSend = sa_s;

		// Response payload order: SAr2, Nr, TSi, TSr
		payload_list = NewListFast(NULL);

		Add(payload_list, IkeV2BuildChildSaResponseProposal(ike, &child_setting, our_spi));

		Add(payload_list, IkeNewDataPayload(IKEV2_PAYLOAD_NONCE, responder_rand->Buf, responder_rand->Size));

		{
			IKEV2_PACKET_TS_PAYLOAD *tsi = &tsi_payload->Payload.TsV2;
			IKEV2_PACKET_TS_PAYLOAD *tsr = &tsr_payload->Payload.TsV2;

			if (LIST_NUM(tsi->TsList) >= 1 && LIST_NUM(tsr->TsList) >= 1)
			{
				IKEV2_TS *echo_i = ZeroMalloc(sizeof(IKEV2_TS));
				IKEV2_TS *echo_r = ZeroMalloc(sizeof(IKEV2_TS));

				Copy(echo_i, LIST_DATA(tsi->TsList, 0), sizeof(IKEV2_TS));
				Copy(echo_r, LIST_DATA(tsr->TsList, 0), sizeof(IKEV2_TS));

				Add(payload_list, IkeV2NewTsPayload(IKEV2_PAYLOAD_TS_INITIATOR, NewListSingle(echo_i)));
				Add(payload_list, IkeV2NewTsPayload(IKEV2_PAYLOAD_TS_RESPONDER, NewListSingle(echo_r)));
			}
			else
			{
				IkeFreePayloadList(payload_list);
				FreeBuf(responder_rand);
				IkeV2MarkIkeSaDeleted(ike, sa);
				return;
			}
		}

		IkeV2SendEncryptedResponse(ike, sa, IKE_EXCHANGE_TYPE_CREATE_CHILD_SA, header->MessageId, payload_list);

		FreeBuf(responder_rand);

		IPsecLog(ike, c, sa, sa_c, "LI2_CHILD_SA_REKEYED",
			sa->InitiatorCookie, sa->ResponderCookie, our_spi, 0, 0);
	}
}
