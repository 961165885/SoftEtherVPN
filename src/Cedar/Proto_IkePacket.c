// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IkePacket.c
// IKE (ISAKMP) packet processing

#include "Proto_IkePacket.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

// Convert the string to a password
BUF *IkeStrToPassword(char *str)
{
	BUF *b;
	// Validate arguments
	if (str == NULL)
	{
		return NewBuf();
	}

	if (StartWith(str, "0x") == false)
	{
		// Accept the string as is
		b = NewBuf();
		WriteBuf(b, str, StrLen(str));
	}
	else
	{
		// Interpret as a hexadecimal value
		b = StrToBin(str + 2);
	}

	return b;
}

// Build a data payload
BUF *IkeBuildDataPayload(IKE_PACKET_DATA_PAYLOAD *t)
{
	BUF *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, t->Data->Buf, t->Data->Size);

	return b;
}

// Build a SA payload
BUF *IkeBuildSaPayload(IKE_PACKET_SA_PAYLOAD *t)
{
	IKE_SA_HEADER h;
	BUF *ret;
	BUF *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.DoI = Endian32(IKE_SA_DOI_IPSEC);
	h.Situation = Endian32(IKE_SA_SITUATION_IDENTITY);

	ret = NewBuf();

	WriteBuf(ret, &h, sizeof(h));

	b = IkeBuildPayloadList(t->PayloadList);
	WriteBufBuf(ret, b);

	FreeBuf(b);

	return ret;
}

// Build a proposal payload
BUF *IkeBuildProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t)
{
	IKE_PROPOSAL_HEADER h;
	BUF *ret, *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.Number = t->Number;
	h.NumTransforms = LIST_NUM(t->PayloadList);
	h.ProtocolId = t->ProtocolId;
	h.SpiSize = t->Spi->Size;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, t->Spi);

	b = IkeBuildPayloadList(t->PayloadList);
	WriteBufBuf(ret, b);

	FreeBuf(b);

	return ret;
}

// Build the transform value list
BUF *IkeBuildTransformValueList(LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(o, i);
		BUF *tmp = IkeBuildTransformValue(v);

		WriteBufBuf(b, tmp);

		FreeBuf(tmp);
	}

	return b;
}

// Build a transform value
BUF *IkeBuildTransformValue(IKE_PACKET_TRANSFORM_VALUE *v)
{
	BUF *b;
	UCHAR af_bit, type;
	USHORT size_or_value;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	type = v->Type;

	if (v->Value >= 65536)
	{
		// 32 bit
		af_bit = 0;
		size_or_value = Endian16(sizeof(UINT));
	}
	else
	{
		// 16 bit
		af_bit = 0x80;
		size_or_value = Endian16((USHORT)v->Value);
	}

	b = NewBuf();
	WriteBuf(b, &af_bit, sizeof(af_bit));
	WriteBuf(b, &type, sizeof(type));
	WriteBuf(b, &size_or_value, sizeof(size_or_value));

	if (af_bit == 0)
	{
		UINT value = Endian32(v->Value);
		WriteBuf(b, &value, sizeof(UINT));
	}

	return b;
}

// Build a transform payload
BUF *IkeBuildTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t)
{
	IKE_TRANSFORM_HEADER h;
	BUF *ret, *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.Number = t->Number;
	h.TransformId = t->TransformId;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));

	b = IkeBuildTransformValueList(t->ValueList);
	WriteBufBuf(ret, b);

	FreeBuf(b);

	return ret;
}

// Get the value from the transform payload
UINT IkeGetTransformValue(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type, UINT index)
{
	UINT i;
	UINT num;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(t->ValueList);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(t->ValueList, i);

		if (v->Type == type)
		{
			if (num == index)
			{
				return v->Value;
			}

			num++;
		}
	}

	return 0;
}

// Get the number of values from the transform payload
UINT IkeGetTransformValueNum(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type)
{
	UINT i;
	UINT num;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(t->ValueList);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(t->ValueList, i);

		if (v->Type == type)
		{
			num++;
		}
	}

	return num;
}

// Build the ID payload
BUF *IkeBuildIdPayload(IKE_PACKET_ID_PAYLOAD *t)
{
	IKE_ID_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.IdType = t->Type;
	h.Port = Endian16(t->Port);
	h.ProtocolId = t->ProtocolId;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));

	WriteBufBuf(ret, t->IdData);

	return ret;
}

// Build a certificate payload
BUF *IkeBuildCertPayload(IKE_PACKET_CERT_PAYLOAD *t)
{
	IKE_CERT_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.CertType = t->CertType;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, t->CertData);

	return ret;
}

// Build a certificate request payload
BUF *IkeBuildCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t)
{
	IKE_CERT_REQUEST_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.CertType = t->CertType;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, t->Data);

	return ret;
}

// Build a notification payload
BUF *IkeBuildNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t)
{
	IKE_NOTICE_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.DoI = Endian32(IKE_SA_DOI_IPSEC);
	h.MessageType = Endian16(t->MessageType);
	h.ProtocolId = t->ProtocolId;
	h.SpiSize = t->Spi->Size;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBuf(ret, t->Spi->Buf, t->Spi->Size);

	if (t->MessageData != NULL)
	{
		WriteBuf(ret, t->MessageData->Buf, t->MessageData->Size);
	}

	return ret;
}

// Build a NAT-OA payload
BUF *IkeBuildNatOaPayload(IKE_PACKET_NAT_OA_PAYLOAD *t)
{
	IKE_NAT_OA_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));

	if (IsIP6(&t->IpAddress))
	{
		h.IdType = IKE_ID_IPV6_ADDR;
	}
	else
	{
		h.IdType = IKE_ID_IPV4_ADDR;
	}

	ret = NewBuf();

	WriteBuf(ret, &h, sizeof(h));

	if (IsIP6(&t->IpAddress))
	{
		WriteBuf(ret, t->IpAddress.address, sizeof(t->IpAddress.address));
	}
	else
	{
		WriteBuf(ret, IPV4(t->IpAddress.address), IPV4_SIZE);
	}

	return ret;
}

// Build a deletion payload
BUF *IkeBuildDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t)
{
	IKE_DELETE_HEADER h;
	BUF *ret;
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.DoI = Endian32(IKE_SA_DOI_IPSEC);
	h.NumSpis = Endian16(LIST_NUM(t->SpiList));
	h.ProtocolId = t->ProtocolId;

	if (LIST_NUM(t->SpiList) >= 1)
	{
		BUF *b = LIST_DATA(t->SpiList, 0);

		h.SpiSize = b->Size;
	}

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));

	for (i = 0;i < LIST_NUM(t->SpiList);i++)
	{
		BUF *b = LIST_DATA(t->SpiList, i);

		WriteBuf(ret, b->Buf, b->Size);
	}

	return ret;
}

// Build a bit array from the payload
BUF *IkeBuildPayload(IKE_PACKET_PAYLOAD *p)
{
	BUF *b = NULL;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	switch (p->PayloadType)
	{
	case IKE_PAYLOAD_SA:					// SA payload
		b = IkeBuildSaPayload(&p->Payload.Sa);
		break;

	case IKE_PAYLOAD_PROPOSAL:			// Proposal payload
		b = IkeBuildProposalPayload(&p->Payload.Proposal);
		break;

	case IKE_PAYLOAD_TRANSFORM:			// Transform payload
		b = IkeBuildTransformPayload(&p->Payload.Transform);
		break;

	case IKE_PAYLOAD_ID:					// ID payload
		b = IkeBuildIdPayload(&p->Payload.Id);
		break;

	case IKE_PAYLOAD_CERT:				// Certificate payload
		b = IkeBuildCertPayload(&p->Payload.Cert);
		break;

	case IKE_PAYLOAD_CERT_REQUEST:		// Certificate request payload
		b = IkeBuildCertRequestPayload(&p->Payload.CertRequest);
		break;

	case IKE_PAYLOAD_NOTICE:			// Notification Payload
		b = IkeBuildNoticePayload(&p->Payload.Notice);
		break;

	case IKE_PAYLOAD_DELETE:			// Deletion payload
		b = IkeBuildDeletePayload(&p->Payload.Delete);
		break;

	case IKE_PAYLOAD_NAT_OA:			// NAT-OA payload
	case IKE_PAYLOAD_NAT_OA_DRAFT:
	case IKE_PAYLOAD_NAT_OA_DRAFT_2:
		b = IkeBuildNatOaPayload(&p->Payload.NatOa);
		break;

	case IKEV2_PAYLOAD_SA:				// SA payload (IKEv2)
		b = IkeV2BuildSaPayload(&p->Payload.SaV2);
		break;

	case IKEV2_PAYLOAD_ID_INITIATOR:		// IDi payload (IKEv2)
	case IKEV2_PAYLOAD_ID_RESPONDER:		// IDr payload (IKEv2)
		b = IkeBuildIdPayload(&p->Payload.Id);
		break;

	case IKEV2_PAYLOAD_NOTIFY:			// Notification payload (IKEv2)
		b = IkeV2BuildNoticePayload(&p->Payload.Notice);
		break;

	case IKEV2_PAYLOAD_DELETE:			// Deletion payload (IKEv2)
		b = IkeV2BuildDeletePayload(&p->Payload.Delete);
		break;

	case IKEV2_PAYLOAD_TS_INITIATOR:		// Traffic selector payload (IKEv2)
	case IKEV2_PAYLOAD_TS_RESPONDER:
		b = IkeV2BuildTsPayload(&p->Payload.TsV2);
		break;

	case IKEV2_PAYLOAD_CONFIGURATION:	// Configuration payload (IKEv2)
		b = IkeV2BuildCpPayload(&p->Payload.CpV2);
		break;

	case IKEV2_PAYLOAD_AUTH:			// AUTH payload (IKEv2)
		b = IkeV2BuildAuthPayload(&p->Payload.AuthV2);
		break;

	case IKE_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload
	case IKE_PAYLOAD_HASH:				// Hash payload
	case IKE_PAYLOAD_SIGN:				// Signature payload
	case IKE_PAYLOAD_RAND:				// Random number payload
	case IKE_PAYLOAD_VENDOR_ID:			// Vendor ID payload
	case IKE_PAYLOAD_NAT_D:				// NAT-D payload
	case IKE_PAYLOAD_NAT_D_DRAFT:		// NAT-D payload (draft)
	default:
		b = IkeBuildDataPayload(&p->Payload.GeneralData);
		break;
	}

	if (b != NULL)
	{
		if (p->BitArray != NULL)
		{
			FreeBuf(p->BitArray);
		}
		p->BitArray = CloneBuf(b);
	}

	return b;
}

// Get the payload type of the first item
UCHAR IkeGetFirstPayloadType(LIST *o)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (o == NULL)
	{
		return IKE_PAYLOAD_NONE;
	}

	if (LIST_NUM(o) == 0)
	{
		return IKE_PAYLOAD_NONE;
	}

	p = (IKE_PACKET_PAYLOAD *)LIST_DATA(o, 0);

	return p->PayloadType;
}

// Build a bit array from the payload list
BUF *IkeBuildPayloadList(LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);
		IKE_PACKET_PAYLOAD *next = NULL;
		IKE_COMMON_HEADER h;
		BUF *tmp;

		if (i < (LIST_NUM(o) - 1))
		{
			next = LIST_DATA(o, i + 1);
		}

		Zero(&h, sizeof(h));
		if (next != NULL)
		{
			h.NextPayload = next->PayloadType;
		}
		else
		{
			h.NextPayload = IKE_PAYLOAD_NONE;
		}

		tmp = IkeBuildPayload(p);
		if (tmp != NULL)
		{
			h.PayloadSize = Endian16(tmp->Size + (USHORT)sizeof(h));

			WriteBuf(b, &h, sizeof(h));
			WriteBuf(b, tmp->Buf, tmp->Size);

			FreeBuf(tmp);
		}
	}

	SeekBuf(b, 0, 0);

	return b;
}

// Get the specified payload
IKE_PACKET_PAYLOAD *IkeGetPayload(LIST *o, UINT payload_type, UINT index)
{
	UINT i, num;
	IKE_PACKET_PAYLOAD *ret = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);

		if (p->PayloadType == payload_type)
		{
			if (num == index)
			{
				ret = p;
				break;
			}

			num++;
		}
	}

	return ret;
}

// Get the number of the payload of the specified type
UINT IkeGetPayloadNum(LIST *o, UINT payload_type)
{
	UINT i, num;
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);

		if (p->PayloadType == payload_type)
		{
			num++;
		}
	}

	return num;
}

// Create a deletion payload
IKE_PACKET_PAYLOAD *IkeNewDeletePayload(UCHAR protocol_id, LIST *spi_list)
{
	IKE_PACKET_PAYLOAD *p;
	if (spi_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_DELETE);
	p->Payload.Delete.ProtocolId = protocol_id;
	p->Payload.Delete.SpiList = spi_list;

	return p;
}

// Create a Notification payload
IKE_PACKET_PAYLOAD *IkeNewNoticePayload(UCHAR protocol_id, USHORT message_type,
										void *spi, UINT spi_size,
										void *message, UINT message_size)
{
	IKE_PACKET_PAYLOAD *p;
	if (spi == NULL && spi_size != 0)
	{
		return NULL;
	}
	if (message == NULL && message_size != 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_NOTICE);
	p->Payload.Notice.MessageType = message_type;
	p->Payload.Notice.MessageData = MemToBuf(message, message_size);
	p->Payload.Notice.Spi = MemToBuf(spi, spi_size);
	p->Payload.Notice.ProtocolId = protocol_id;

	return p;
}

// Create a Invalid Cookie Payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidCookiePayload(UINT64 init_cookie, UINT64 resp_cookie)
{
	IKE_PACKET_PAYLOAD *ret;
	BUF *b = NewBuf();

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IKE, IKE_NOTICE_ERROR_INVALID_COOKIE, b->Buf, b->Size,
		b->Buf, b->Size);

	FreeBuf(b);

	return ret;
}

// Create an Invalid SPI payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidSpiPayload(UINT spi)
{
	IKE_PACKET_PAYLOAD *ret;
	spi = Endian32(spi);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IPSEC_ESP, IKE_NOTICE_ERROR_INVALID_SPI, &spi, sizeof(UINT),
		&spi, sizeof(UINT));

	return ret;
}

// Create a No Proposal Chosen payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorNoProposalChosenPayload(bool quick_mode, UINT64 init_cookie, UINT64 resp_cookie)
{
	BUF *b = NewBuf();
	IKE_PACKET_PAYLOAD *ret;

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload((quick_mode ? IKE_PROTOCOL_ID_IPSEC_ESP : IKE_PROTOCOL_ID_IKE),
		IKE_NOTICE_ERROR_NO_PROPOSAL_CHOSEN, b->Buf, b->Size,
		NULL, 0);

	FreeBuf(b);

	return ret;
}

// Create a DPD payload
IKE_PACKET_PAYLOAD *IkeNewNoticeDpdPayload(bool ack, UINT64 init_cookie, UINT64 resp_cookie, UINT seq_no)
{
	IKE_PACKET_PAYLOAD *ret;
	BUF *b = NewBuf();

	seq_no = Endian32(seq_no);

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IKE, (ack ? IKE_NOTICE_DPD_RESPONSE : IKE_NOTICE_DPD_REQUEST),
		b->Buf, b->Size,
		&seq_no, sizeof(UINT));

	FreeBuf(b);

	return ret;
}

// Create an ID payload
IKE_PACKET_PAYLOAD *IkeNewIdPayload(UCHAR id_type, UCHAR protocol_id, USHORT port, void *id_data, UINT id_size)
{
	IKE_PACKET_PAYLOAD *p;
	if (id_data == NULL && id_size != 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_ID);
	p->Payload.Id.IdData = MemToBuf(id_data, id_size);
	p->Payload.Id.Port = port;
	p->Payload.Id.ProtocolId = protocol_id;
	p->Payload.Id.Type = id_type;

	return p;
}

// Create a transform payload
IKE_PACKET_PAYLOAD *IkeNewTransformPayload(UCHAR number, UCHAR transform_id, LIST *value_list)
{
	IKE_PACKET_PAYLOAD *p;
	if (value_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_TRANSFORM);
	p->Payload.Transform.Number = number;
	p->Payload.Transform.TransformId = transform_id;
	p->Payload.Transform.ValueList = value_list;

	return p;
}

// Create a proposal payload
IKE_PACKET_PAYLOAD *IkeNewProposalPayload(UCHAR number, UCHAR protocol_id, void *spi, UINT spi_size, LIST *payload_list)
{
	IKE_PACKET_PAYLOAD *p;
	if (payload_list == NULL || (spi == NULL && spi_size != 0))
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_PROPOSAL);
	p->Payload.Proposal.Number = number;
	p->Payload.Proposal.ProtocolId = protocol_id;
	p->Payload.Proposal.Spi = MemToBuf(spi, spi_size);
	p->Payload.Proposal.PayloadList = payload_list;

	return p;
}

// Create an SA payload
IKE_PACKET_PAYLOAD *IkeNewSaPayload(LIST *payload_list)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (payload_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_SA);
	p->Payload.Sa.PayloadList = payload_list;

	return p;
}

// Create a NAT-OA payload
IKE_PACKET_PAYLOAD *IkeNewNatOaPayload(UCHAR payload_type, IP *ip)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (ip == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(payload_type);
	Copy(&p->Payload.NatOa.IpAddress, ip, sizeof(IP));
	p->PayloadType = payload_type;

	return p;
}

// Create a data payload
IKE_PACKET_PAYLOAD *IkeNewDataPayload(UCHAR payload_type, void *data, UINT size)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(payload_type);
	p->Payload.GeneralData.Data = MemToBuf(data, size);

	return p;
}

// Create a new payload
IKE_PACKET_PAYLOAD *IkeNewPayload(UINT payload_type)
{
	IKE_PACKET_PAYLOAD *p;

	p = ZeroMalloc(sizeof(IKE_PACKET_PAYLOAD));

	p->PayloadType = payload_type;

	return p;
}

// Analyse the IKE payload body
IKE_PACKET_PAYLOAD *IkeParsePayload(UINT payload_type, BUF *b)
{
	IKE_PACKET_PAYLOAD *p = NULL;
	bool ok = true;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(IKE_PACKET_PAYLOAD));
	p->PayloadType = payload_type;

	switch (p->PayloadType)
	{
	case IKE_PAYLOAD_SA:					// SA payload
		ok = IkeParseSaPayload(&p->Payload.Sa, b);
		break;

	case IKE_PAYLOAD_PROPOSAL:			// Proposal payload
		ok = IkeParseProposalPayload(&p->Payload.Proposal, b);
		break;

	case IKE_PAYLOAD_TRANSFORM:			// Proposal payload
		ok = IkeParseTransformPayload(&p->Payload.Transform, b);
		break;

	case IKE_PAYLOAD_ID:					// ID payload
		ok = IkeParseIdPayload(&p->Payload.Id, b);
		break;

	case IKE_PAYLOAD_CERT:				// Certificate payload
	case IKEV2_PAYLOAD_CERT:
		ok = IkeParseCertPayload(&p->Payload.Cert, b);
		break;

	case IKE_PAYLOAD_CERT_REQUEST:		// Certificate request payload
	case IKEV2_PAYLOAD_CERTREQ:
		ok = IkeParseCertRequestPayload(&p->Payload.CertRequest, b);
		break;

	case IKE_PAYLOAD_NOTICE:				// Notification Payload
		ok = IkeParseNoticePayload(&p->Payload.Notice, b);
		break;

	case IKE_PAYLOAD_DELETE:				// Deletion payload
		ok = IkeParseDeletePayload(&p->Payload.Delete, b);
		break;

	case IKE_PAYLOAD_NAT_OA:
	case IKE_PAYLOAD_NAT_OA_DRAFT:
	case IKE_PAYLOAD_NAT_OA_DRAFT_2:
		ok = IkeParseNatOaPayload(&p->Payload.NatOa, b);
		break;
	case IKEV2_PAYLOAD_SA:					// SA payload (IKEv2)
		ok = IkeV2ParseSaPayload(&p->Payload.SaV2, b);
		break;

	case IKEV2_PAYLOAD_ID_INITIATOR:		// IDi payload (IKEv2)
	case IKEV2_PAYLOAD_ID_RESPONDER:		// IDr payload (IKEv2)
		ok = IkeParseIdPayload(&p->Payload.Id, b);
		break;

	case IKEV2_PAYLOAD_NOTIFY:				// Notification payload (IKEv2)
		ok = IkeV2ParseNotifyPayload(&p->Payload.Notice, b);
		break;

	case IKEV2_PAYLOAD_DELETE:				// Deletion payload (IKEv2)
		ok = IkeV2ParseDeletePayload(&p->Payload.Delete, b);
		break;

	case IKEV2_PAYLOAD_TS_INITIATOR:		// Traffic selector payload (IKEv2)
	case IKEV2_PAYLOAD_TS_RESPONDER:
		ok = IkeV2ParseTsPayload(&p->Payload.TsV2, b);
		break;

	case IKEV2_PAYLOAD_CONFIGURATION:		// Configuration payload (IKEv2)
		ok = IkeV2ParseCpPayload(&p->Payload.CpV2, b);
		break;

	case IKEV2_PAYLOAD_AUTH:				// AUTH payload (IKEv2)
		ok = IkeV2ParseAuthPayload(&p->Payload.AuthV2, b);
		break;

	case IKE_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload
	case IKE_PAYLOAD_HASH:				// Hash payload
	case IKE_PAYLOAD_SIGN:				// Signature payload
	case IKE_PAYLOAD_RAND:				// Random number payload
	case IKE_PAYLOAD_VENDOR_ID:			// Vendor ID payload
	case IKE_PAYLOAD_NAT_D:				// NAT-D payload
	case IKE_PAYLOAD_NAT_D_DRAFT:		// NAT-D payload (draft)
	case IKEV2_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload (IKEv2)
	case IKEV2_PAYLOAD_NONCE:				// Nonce payload (IKEv2)
	case IKEV2_PAYLOAD_VENDOR_ID:			// Vendor ID payload (IKEv2)
	case IKEV2_PAYLOAD_ENCRYPTED:			// Encrypted payload (IKEv2)
	case IKEV2_PAYLOAD_EAP:				// EAP payload (IKEv2)
	default:
		ok = IkeParseDataPayload(&p->Payload.GeneralData, b);
		break;
	}

	if (ok == false)
	{
		Free(p);
		p = NULL;
	}
	else
	{
		p->BitArray = CloneBuf(b);
	}

	return p;
}

// Parse the SA payload
bool IkeParseSaPayload(IKE_PACKET_SA_PAYLOAD *t, BUF *b)
{
	IKE_SA_HEADER *h;
	UCHAR *buf;
	UINT size;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (b->Size < sizeof(IKE_SA_HEADER))
	{
		return false;
	}

	h = (IKE_SA_HEADER *)b->Buf;
	buf = (UCHAR *)b->Buf;
	buf += sizeof(IKE_SA_HEADER);
	size = b->Size - sizeof(IKE_SA_HEADER);

	if (Endian32(h->DoI) != IKE_SA_DOI_IPSEC)
	{
		Debug("ISAKMP: Invalid DoI Value: 0x%x\n", Endian32(h->DoI));
		return false;
	}

	if (Endian32(h->Situation) != IKE_SA_SITUATION_IDENTITY)
	{
		Debug("ISAKMP: Invalid Situation Value: 0x%x\n", Endian32(h->Situation));
		return false;
	}

	t->PayloadList = IkeParsePayloadList(buf, size, IKE_PAYLOAD_PROPOSAL);

	return true;
}

// Release the SA payload
void IkeFreeSaPayload(IKE_PACKET_SA_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->PayloadList != NULL)
	{
		IkeFreePayloadList(t->PayloadList);
		t->PayloadList = NULL;
	}
}

// Parse the proposal payload
bool IkeParseProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t, BUF *b)
{
	IKE_PROPOSAL_HEADER *h;
	UCHAR *buf;
	UINT size;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (b->Size < sizeof(IKE_PROPOSAL_HEADER))
	{
		return false;
	}

	h = (IKE_PROPOSAL_HEADER *)b->Buf;

	t->Number = h->Number;
	t->ProtocolId = h->ProtocolId;

	buf = (UCHAR *)b->Buf;
	buf += sizeof(IKE_PROPOSAL_HEADER);
	size = b->Size - sizeof(IKE_PROPOSAL_HEADER);

	if (size < (UINT)h->SpiSize)
	{
		return false;
	}

	t->Spi = MemToBuf(buf, h->SpiSize);

	buf += h->SpiSize;
	size -= h->SpiSize;

	t->PayloadList = IkeParsePayloadList(buf, size, IKE_PAYLOAD_TRANSFORM);

	return true;
}

// Release the proposal payload
void IkeFreeProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->Spi != NULL)
	{
		FreeBuf(t->Spi);
		t->Spi = NULL;
	}

	if (t->PayloadList != NULL)
	{
		IkeFreePayloadList(t->PayloadList);
		t->PayloadList = NULL;
	}
}

// Parse the transform payload
bool IkeParseTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t, BUF *b)
{
	IKE_TRANSFORM_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->Number = h.Number;
	t->TransformId = h.TransformId;
	t->ValueList = IkeParseTransformValueList(b);

	return true;
}

// Create a new transform value
IKE_PACKET_TRANSFORM_VALUE *IkeNewTransformValue(UCHAR type, UINT value)
{
	IKE_PACKET_TRANSFORM_VALUE *v = ZeroMalloc(sizeof(IKE_PACKET_TRANSFORM_VALUE));

	v->Type = type;
	v->Value = value;

	return v;
}

// Parse the transform value list
LIST *IkeParseTransformValueList(BUF *b)
{
	LIST *o;
	bool ok = true;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	while (b->Current < b->Size)
	{
		UCHAR af_bit, type;
		USHORT size;
		UINT value = 0;
		IKE_PACKET_TRANSFORM_VALUE *v;

		if (ReadBuf(b, &af_bit, sizeof(af_bit)) != sizeof(af_bit))
		{
			ok = false;
			break;
		}

		if (ReadBuf(b, &type, sizeof(type)) != sizeof(type))
		{
			ok = false;
			break;
		}

		if (ReadBuf(b, &size, sizeof(size)) != sizeof(size))
		{
			ok = false;
		}

		size = Endian16(size);

		if (af_bit == 0)
		{
			UCHAR *tmp = Malloc(size);

			if (ReadBuf(b, tmp, size) != size)
			{
				ok = false;
				Free(tmp);
				break;
			}

			switch (size)
			{
			case sizeof(UINT):
				value = READ_UINT(tmp);
				break;

			case sizeof(USHORT):
				value = READ_USHORT(tmp);
				break;

			case sizeof(UCHAR):
				value = *((UCHAR *)tmp);
				break;
			}

			Free(tmp);
		}
		else
		{
			value = (UINT)size;
		}

		v = ZeroMalloc(sizeof(IKE_PACKET_TRANSFORM_VALUE));
		v->Type = type;
		v->Value = value;

		Add(o, v);
	}

	if (ok == false)
	{
		IkeFreeTransformValueList(o);
		o = NULL;
	}

	return o;
}

// Release the transform value list
void IkeFreeTransformValueList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(o, i);

		Free(v);
	}

	ReleaseList(o);
}

// Release the transform payload
void IkeFreeTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->ValueList != NULL)
	{
		IkeFreeTransformValueList(t->ValueList);
		t->ValueList = NULL;
	}
}

// Parse the ID payload
bool IkeParseIdPayload(IKE_PACKET_ID_PAYLOAD *t, BUF *b)
{
	IKE_ID_HEADER h;
	IP ip;
	IP subnet;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->Type = h.IdType;
	t->ProtocolId = h.ProtocolId;
	t->Port = Endian16(h.Port);
	t->IdData = ReadRemainBuf(b);
	if (t->IdData == NULL)
	{
		return false;
	}

	ZeroIP4(&ip);
	ZeroIP4(&subnet);

	// Convert to string
	Zero(t->StrData, sizeof(t->StrData));
	switch (t->Type)
	{
	case IKE_ID_FQDN:
	case IKE_ID_USER_FQDN:
	case IKE_ID_KEY_ID:
		Copy(t->StrData, t->IdData->Buf, MIN(t->IdData->Size, sizeof(t->StrData) - 1));
		break;

	case IKE_ID_IPV4_ADDR:
		if (t->IdData->Size == IPV4_SIZE)
		{
			Copy(IPV4(ip.address), t->IdData->Buf, IPV4_SIZE);

			IPToStr(t->StrData, sizeof(t->StrData), &ip);
		}
		break;

	case IKE_ID_IPV6_ADDR:
		if (t->IdData->Size == 16)
		{
			SetIP6(&ip, t->IdData->Buf);

			IPToStr(t->StrData, sizeof(t->StrData), &ip);
		}
		break;

	case IKE_ID_IPV4_ADDR_SUBNET:
		if (t->IdData->Size == IPV4_SIZE * 2)
		{
			char ipstr[MAX_SIZE];
			char subnetstr[MAX_SIZE];
			Copy(IPV4(ip.address), t->IdData->Buf, IPV4_SIZE);
			Copy(IPV4(subnet.address), ((BYTE *)t->IdData->Buf) + IPV4_SIZE, IPV4_SIZE);

			IPToStr(ipstr, sizeof(ipstr), &ip);
			MaskToStr(subnetstr, sizeof(subnetstr), &subnet);

			Format(t->StrData, sizeof(t->StrData), "%s/%s", ipstr, subnetstr);
		}
		break;

	case IKE_ID_IPV6_ADDR_SUBNET:
		if (t->IdData->Size == 32)
		{
			char ipstr[MAX_SIZE];
			char subnetstr[MAX_SIZE];
			SetIP6(&ip, t->IdData->Buf);
			SetIP6(&subnet, ((UCHAR *)t->IdData->Buf) + 16);

			IPToStr(ipstr, sizeof(ipstr), &ip);
			MaskToStr(subnetstr, sizeof(subnetstr), &subnet);

			Format(t->StrData, sizeof(t->StrData), "%s/%s", ipstr, subnetstr);
		}
		break;
	}

	return true;
}

// Release the ID payload
void IkeFreeIdPayload(IKE_PACKET_ID_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->IdData != NULL)
	{
		FreeBuf(t->IdData);
		t->IdData = NULL;
	}
}

// Parse the certificate payload
bool IkeParseCertPayload(IKE_PACKET_CERT_PAYLOAD *t, BUF *b)
{
	IKE_CERT_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->CertType = h.CertType;
	t->CertData = ReadRemainBuf(b);
	if (t->CertData == NULL)
	{
		return false;
	}

	return true;
}

// Release the certificate payload
void IkeFreeCertPayload(IKE_PACKET_CERT_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->CertData != NULL)
	{
		FreeBuf(t->CertData);
		t->CertData = NULL;
	}
}

// Parse the certificate request payload
bool IkeParseCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t, BUF *b)
{
	IKE_CERT_REQUEST_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->CertType = h.CertType;
	t->Data = ReadRemainBuf(b);
	if (t->Data == NULL)
	{
		return false;
	}

	return true;
}

// Release the certificate request payload
void IkeFreeCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->Data != NULL)
	{
		FreeBuf(t->Data);
		t->Data = NULL;
	}
}

// Parse the notification payload
bool IkeParseNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t, BUF *b)
{
	IKE_NOTICE_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	if (Endian32(h.DoI) != IKE_SA_DOI_IPSEC)
	{
		Debug("ISAKMP: Invalid DoI Value: 0x%x\n", Endian32(h.DoI));
		return false;
	}

	t->MessageType = Endian16(h.MessageType);
	t->ProtocolId = h.ProtocolId;
	t->Spi = ReadBufFromBuf(b, h.SpiSize);
	if (t->Spi == NULL)
	{
		return false;
	}
	t->MessageData = ReadRemainBuf(b);

	return true;
}

// Release the notification payload
void IkeFreeNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->MessageData != NULL)
	{
		FreeBuf(t->MessageData);
		t->MessageData = NULL;
	}

	if (t->Spi != NULL)
	{
		FreeBuf(t->Spi);
		t->Spi = NULL;
	}
}

// Parse the NAT-OA payload
bool IkeParseNatOaPayload(IKE_PACKET_NAT_OA_PAYLOAD *t, BUF *b)
{
	IKE_NAT_OA_HEADER h;
	UCHAR ip4[4];
	UCHAR ip6[16];
	IP ip;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	Zero(&ip, sizeof(ip));

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	if (h.IdType != IKE_ID_IPV4_ADDR && h.IdType != IKE_ID_IPV6_ADDR)
	{
		return false;
	}

	switch (h.IdType)
	{
	case IKE_ID_IPV4_ADDR:	// IPv4
		if (ReadBuf(b, ip4, sizeof(ip4)) != sizeof(ip4))
		{
			return false;
		}

		SetIP(&ip, ip4[0], ip4[1], ip4[2], ip4[3]);

		break;

	case IKE_ID_IPV6_ADDR:	// IPv6
		if (ReadBuf(b, ip6, sizeof(ip6)) != sizeof(ip6))
		{
			return false;
		}

		SetIP6(&ip, ip6);

		break;

	default:
		return false;
	}

	Copy(&t->IpAddress, &ip, sizeof(IP));

	return true;
}

// Parse the deletion payload
bool IkeParseDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t, BUF *b)
{
	IKE_DELETE_HEADER h;
	UINT num_spi;
	UINT spi_size;
	UINT i;
	bool ok = true;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	if (Endian32(h.DoI) != IKE_SA_DOI_IPSEC)
	{
		Debug("ISAKMP: Invalid DoI Value: 0x%x\n", Endian32(h.DoI));
		return false;
	}

	t->ProtocolId = h.ProtocolId;
	t->SpiList = NewListFast(NULL);
	num_spi = Endian16(h.NumSpis);
	spi_size = h.SpiSize;

	for (i = 0;i < num_spi;i++)
	{
		BUF *spi = ReadBufFromBuf(b, spi_size);

		if (spi == NULL)
		{
			ok = false;
			break;
		}

		Add(t->SpiList, spi);
	}

	if (ok == false)
	{
		IkeFreeDeletePayload(t);
		return false;
	}

	return true;
}

// Release the deletion payload
void IkeFreeDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->SpiList != NULL)
	{
		for (i = 0;i < LIST_NUM(t->SpiList);i++)
		{
			BUF *spi = LIST_DATA(t->SpiList, i);

			FreeBuf(spi);
		}

		ReleaseList(t->SpiList);

		t->SpiList = NULL;
	}
}

// Check whether the hash matches
bool IkeCompareHash(IKE_PACKET_PAYLOAD *hash_payload, void *hash_data, UINT hash_size)
{
	//char tmp1[MAX_SIZE], tmp2[MAX_SIZE];
	// Validate arguments
	if (hash_payload == NULL || hash_data == NULL || hash_size == 0)
	{
		return false;
	}

	if (hash_payload->PayloadType != IKE_PAYLOAD_HASH)
	{
		return false;
	}

	if (hash_payload->Payload.Hash.Data == NULL)
	{
		return false;
	}

	if (hash_payload->Payload.Hash.Data->Size != hash_size)
	{
		return false;
	}

	//BinToStrEx(tmp1, sizeof(tmp1), hash_payload->Payload.Hash.Data->Buf, hash_size);
	//BinToStrEx(tmp2, sizeof(tmp2), hash_data, hash_size);

	//Debug("IkeCompareHash\n  1: %s\n  2: %s\n", tmp1, tmp2);

	if (Cmp(hash_payload->Payload.Hash.Data->Buf, hash_data, hash_size) != 0)
	{
		return false;
	}

	return true;
}

// Parse the data payload
bool IkeParseDataPayload(IKE_PACKET_DATA_PAYLOAD *t, BUF *b)
{
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	t->Data = MemToBuf(b->Buf, b->Size);

	return true;
}

// Release the data payload
void IkeFreeDataPayload(IKE_PACKET_DATA_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeBuf(t->Data);
}

// Release the IKE payload body
void IkeFreePayload(IKE_PACKET_PAYLOAD *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	switch (p->PayloadType)
	{
	case IKE_PAYLOAD_SA:					// SA payload
		IkeFreeSaPayload(&p->Payload.Sa);
		break;

	case IKE_PAYLOAD_PROPOSAL:			// Proposal payload
		IkeFreeProposalPayload(&p->Payload.Proposal);
		break;

	case IKE_PAYLOAD_TRANSFORM:			// Proposal payload
		IkeFreeTransformPayload(&p->Payload.Transform);
		break;

	case IKE_PAYLOAD_ID:					// ID payload
		IkeFreeIdPayload(&p->Payload.Id);
		break;

	case IKE_PAYLOAD_CERT:				// Certificate payload
		IkeFreeCertPayload(&p->Payload.Cert);
		break;

	case IKE_PAYLOAD_CERT_REQUEST:		// Certificate request payload
		IkeFreeCertRequestPayload(&p->Payload.CertRequest);
		break;

	case IKE_PAYLOAD_NOTICE:				// Notification Payload
		IkeFreeNoticePayload(&p->Payload.Notice);
		break;

	case IKE_PAYLOAD_DELETE:				// Deletion payload
		IkeFreeDeletePayload(&p->Payload.Delete);
		break;

	case IKE_PAYLOAD_NAT_OA:				// NAT-OD payload
	case IKE_PAYLOAD_NAT_OA_DRAFT:
	case IKE_PAYLOAD_NAT_OA_DRAFT_2:
		// Do Nothing
		break;

	case IKEV2_PAYLOAD_SA:				// SA payload (IKEv2)
		IkeV2FreeSaPayload(&p->Payload.SaV2);
		break;

	case IKEV2_PAYLOAD_ID_INITIATOR:		// IDi payload (IKEv2)
	case IKEV2_PAYLOAD_ID_RESPONDER:		// IDr payload (IKEv2)
		IkeFreeIdPayload(&p->Payload.Id);
		break;

	case IKEV2_PAYLOAD_NOTIFY:				// Notification payload (IKEv2)
		IkeFreeNoticePayload(&p->Payload.Notice);
		break;

	case IKEV2_PAYLOAD_DELETE:				// Deletion payload (IKEv2)
		IkeFreeDeletePayload(&p->Payload.Delete);
		break;

	case IKEV2_PAYLOAD_TS_INITIATOR:		// Traffic selector payload (IKEv2)
	case IKEV2_PAYLOAD_TS_RESPONDER:
		IkeV2FreeTsPayload(&p->Payload.TsV2);
		break;

	case IKEV2_PAYLOAD_CONFIGURATION:		// Configuration payload (IKEv2)
		IkeV2FreeCpPayload(&p->Payload.CpV2);
		break;

	case IKEV2_PAYLOAD_AUTH:				// AUTH payload (IKEv2)
		IkeV2FreeAuthPayload(&p->Payload.AuthV2);
		break;

	case IKE_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload
	case IKE_PAYLOAD_HASH:				// Hash payload
	case IKE_PAYLOAD_SIGN:				// Signature payload
	case IKE_PAYLOAD_RAND:				// Random number payload
	case IKE_PAYLOAD_VENDOR_ID:			// Vendor ID payload
	case IKE_PAYLOAD_NAT_D:				// NAT-D payload
	case IKE_PAYLOAD_NAT_D_DRAFT:		// NAT-D payload (draft)
	default:
		IkeFreeDataPayload(&p->Payload.GeneralData);
		break;
	}

	if (p->BitArray != NULL)
	{
		FreeBuf(p->BitArray);
	}

	Free(p);
}

// Analyse the IKE payload list
LIST *IkeParsePayloadList(void *data, UINT size, UCHAR first_payload)
{
	return IkeParsePayloadListEx(data, size, first_payload, NULL);
}
LIST *IkeParsePayloadListEx(void *data, UINT size, UCHAR first_payload, UINT *total_read_size)
{
	LIST *o;
	BUF *b;
	UCHAR payload_type = first_payload;
	UINT total = 0;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);
	b = MemToBuf(data, size);

	while (payload_type != IKE_PAYLOAD_NONE)
	{
		// Read the common header
		IKE_COMMON_HEADER header;
		USHORT payload_size;
		BUF *payload_data;
		IKE_PACKET_PAYLOAD *pay;

		if (ReadBuf(b, &header, sizeof(header)) != sizeof(header))
		{
			Debug("ISAKMP: Broken Packet (Invalid Payload Size)\n");

LABEL_ERROR:
			// Header reading failure
			IkeFreePayloadList(o);
			o = NULL;

			break;
		}

		total += sizeof(header);

		// Get the payload size
		payload_size = Endian16(header.PayloadSize);

		if (payload_size < sizeof(header))
		{
			Debug("ISAKMP: Broken Packet (Invalid Payload Size)\n");
			goto LABEL_ERROR;
		}

		payload_size -= sizeof(header);

		// Read the payload data
		payload_data = ReadBufFromBuf(b, payload_size);
		if (payload_data == NULL)
		{
			// Data read failure
			Debug("ISAKMP: Broken Packet (Invalid Payload Data)\n");
			goto LABEL_ERROR;
		}

		total += payload_size;

		// Analyse the payload body
		if (!IKE_IS_SUPPORTED_PAYLOAD_TYPE(payload_type))
		{
			// Unsupported payload type
			Debug("ISAKMP: Ignored Payload Type: %u\n", payload_type);
		}
		pay = IkeParsePayload(payload_type, payload_data);

		if (pay == NULL)
		{
			FreeBuf(payload_data);
			Debug("ISAKMP: Broken Packet (Payload Data Parse Failed)\n");
			goto LABEL_ERROR;
		}

		Add(o, pay);

		payload_type = header.NextPayload;

		FreeBuf(payload_data);
	}

	FreeBuf(b);

	if (total_read_size != NULL)
	{
		*total_read_size = total;
	}

	return o;
}

// Release the IKE payload list
void IkeFreePayloadList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);

		IkeFreePayload(p);
	}

	ReleaseList(o);
}

// Build an IKE packet
BUF *IkeBuild(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam)
{
	return IkeBuildEx(p, cparam, false);
}
BUF *IkeBuildEx(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam, bool use_original_decrypted)
{
	IKE_HEADER h;
	BUF *msg_buf;
	BUF *ret;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	if (p->PayloadList == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.InitiatorCookie = Endian64(p->InitiatorCookie);
	h.ResponderCookie = Endian64(p->ResponderCookie);
	h.NextPayload = IkeGetFirstPayloadType(p->PayloadList);
	h.ExchangeType = p->ExchangeType;

	if (p->MajorVersion == IKE_MAJOR_VERSION_2)
	{
		h.MajorVersion = IKE_MAJOR_VERSION_2;
		h.MinorVersion = 0;
		h.Flag = (p->FlagV2Initiator ? IKE_HEADER_V2_FLAG_INITIATOR : 0) |
			(p->FlagV2Version ? IKE_HEADER_V2_FLAG_VERSION : 0) |
			(p->FlagV2Response ? IKE_HEADER_V2_FLAG_RESPONSE : 0);
	}
	else
	{
		h.MajorVersion = IKE_MAJOR_VERSION_1;
		h.Flag = (p->FlagEncrypted ? IKE_HEADER_FLAG_ENCRYPTED : 0) |
			(p->FlagCommit ? IKE_HEADER_FLAG_COMMIT : 0) |
			(p->FlagAuthOnly ? IKE_HEADER_FLAG_AUTH_ONLY : 0);
	}

	h.MessageId = Endian32(p->MessageId);

	if (p->DecryptedPayload != NULL && use_original_decrypted)
	{
		msg_buf = CloneBuf(p->DecryptedPayload);
	}
	else
	{
		msg_buf = IkeBuildPayloadList(p->PayloadList);
	}

	if (p->DecryptedPayload != NULL)
	{
		FreeBuf(p->DecryptedPayload);
	}

	p->DecryptedPayload = CloneBuf(msg_buf);

	if (p->FlagEncrypted)
	{
		BUF *b;
		// Encryption
		b = IkeEncryptWithPadding(msg_buf->Buf, msg_buf->Size, cparam);

		if (b == NULL)
		{
			Debug("ISAKMP: Packet Encrypt Failed\n");
			FreeBuf(msg_buf);
			return NULL;
		}

		FreeBuf(msg_buf);

		msg_buf = b;
	}

	h.MessageSize = Endian32(msg_buf->Size + sizeof(h));

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, msg_buf);

	FreeBuf(msg_buf);

	SeekBuf(ret, 0, 0);

	return ret;
}

// Analyse the IKE packet
IKE_PACKET *IkeParseEx(void *data, UINT size, IKE_CRYPTO_PARAM *cparam, bool header_only)
{
	IKE_PACKET *p = NULL;
	BUF *b;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	b = MemToBuf(data, size);

	if (b->Size < sizeof(IKE_HEADER))
	{
		Debug("ISAKMP: Invalid Packet Size\n");
	}
	else
	{
		// Header analysis
		IKE_HEADER *h = (IKE_HEADER *)b->Buf;

		p = ZeroMalloc(sizeof(IKE_PACKET));

		p->MessageSize = Endian32(h->MessageSize);
		p->InitiatorCookie = Endian64(h->InitiatorCookie);
		p->ResponderCookie = Endian64(h->ResponderCookie);
		p->MajorVersion = h->MajorVersion;
		p->MinorVersion = h->MinorVersion;
		p->ExchangeType = h->ExchangeType;

		if (p->MajorVersion == IKE_MAJOR_VERSION_2)
		{
			// In IKEv2 the encryption is expressed by the Encrypted (SK)
			// payload, not by a header flag
			p->FlagV2Initiator = (h->Flag & IKE_HEADER_V2_FLAG_INITIATOR) ? true : false;
			p->FlagV2Version = (h->Flag & IKE_HEADER_V2_FLAG_VERSION) ? true : false;
			p->FlagV2Response = (h->Flag & IKE_HEADER_V2_FLAG_RESPONSE) ? true : false;
		}
		else
		{
			p->FlagEncrypted = (h->Flag & IKE_HEADER_FLAG_ENCRYPTED) ? true : false;
			p->FlagCommit = (h->Flag & IKE_HEADER_FLAG_COMMIT) ? true : false;
			p->FlagAuthOnly = (h->Flag & IKE_HEADER_FLAG_AUTH_ONLY) ? true : false;
		}

		p->MessageId = Endian32(h->MessageId);

		if (b->Size < Endian32(h->MessageSize) ||
			Endian32(h->MessageSize) < sizeof(IKE_HEADER))
		{
			Debug("ISAKMP: Invalid Packet Size\n");

			IkeFree(p);
			p = NULL;
		}
		else
		{
			if (header_only == false)
			{
				bool ok = false;
				UCHAR *payload_data;
				UINT payload_size;
				BUF *buf = NULL;

				payload_data = ((UCHAR *)h) + sizeof(IKE_HEADER);
				payload_size = Endian32(h->MessageSize) - sizeof(IKE_HEADER);

				// Decrypt if it is encrypted
				if (p->FlagEncrypted)
				{
					buf = IkeDecrypt(payload_data, payload_size, cparam);

					if (buf != NULL)
					{
						ok = true;

						payload_data = buf->Buf;
						payload_size = buf->Size;

						p->DecryptedPayload = CloneBuf(buf);
					}
				}
				else
				{
					ok = true;
				}

				if (ok == false)
				{
					Debug("ISAKMP: Decrypt Failed\n");

					IkeFree(p);
					p = NULL;
				}
				else
				{
					UINT total_read_size;

					// Payload analysis
					p->PayloadList = IkeParsePayloadListEx(payload_data,
						payload_size,
						h->NextPayload,
						&total_read_size);

					if (p->DecryptedPayload != NULL)
					{
						p->DecryptedPayload->Size = MIN(p->DecryptedPayload->Size, total_read_size);
					}
					else
					{
						p->DecryptedPayload = MemToBuf(payload_data, payload_size);
					}
				}

				if (buf != NULL)
				{
					FreeBuf(buf);
				}
			}
		}
	}

	FreeBuf(b);

	return p;
}
IKE_PACKET *IkeParseHeader(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	return IkeParseEx(data, size, cparam, true);
}
IKE_PACKET *IkeParse(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	return IkeParseEx(data, size, cparam, false);
}

// Send packet for debugging by UDP (For debugging with Ethereal)
void IkeDebugUdpSendRawPacket(IKE_PACKET *p)
{
	BUF *b;
	IP ip;
	SOCK *udp;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->FlagEncrypted = false;

	b = IkeBuildEx(p, NULL, true);

	if (b == NULL)
	{
		return;
	}

	Zero(&ip, sizeof(ip));
	SetIP(&ip, 1, 2, 3, 4);

	udp = NewUDP(0);

	SendTo(udp, &ip, 500, b->Buf, b->Size);

	ReleaseSock(udp);
	FreeBuf(b);
}

// Output the payload list
void IkeDebugPrintPayloads(LIST *o, UINT depth)
{
	UINT i;
	char space[MAX_SIZE];
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	MakeCharArray2(space, ' ', depth * 2);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *payload = LIST_DATA(o, i);

		Debug("%s%u: Type = %u, Size = %u\n", space, i, payload->PayloadType, payload->BitArray->Size);

		switch (payload->PayloadType)
		{
		case IKE_PAYLOAD_SA:
			IkeDebugPrintPayloads(payload->Payload.Sa.PayloadList, depth + 1);
			break;

		case IKE_PAYLOAD_PROPOSAL:
			IkeDebugPrintPayloads(payload->Payload.Proposal.PayloadList, depth + 1);
			break;
		}
	}
}

// Encryption (also with padding)
BUF *IkeEncryptWithPadding(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	UINT total_size;
	UINT i;
	UCHAR n = 0;
	UCHAR *tmp;
	BUF *ret;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (data == NULL || cparam == NULL)
	{
		return NULL;
	}

	total_size = ((size / cparam->Key->Crypto->BlockSize) + ((size % cparam->Key->Crypto->BlockSize) == 0 ? 0 : 1))
		* cparam->Key->Crypto->BlockSize;
	if (total_size == 0)
	{
		total_size = cparam->Key->Crypto->BlockSize;
	}

	if (total_size > sizeof(tmp1600))
	{
		tmp = Malloc(total_size);
	}
	else
	{
		tmp = tmp1600;
		no_free = true;
	}

	Copy(tmp, data, size);

	for (i = size;i < total_size;i++)
	{
		tmp[i] = ++n;
	}

	ret = IkeEncrypt(tmp, total_size, cparam);

	if (no_free == false)
	{
		Free(tmp);
	}

	return ret;
}

// Encryption
BUF *IkeEncrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	void *tmp;
	BUF *b;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (data == NULL || cparam == NULL)
	{
		return NULL;
	}

	if ((size % cparam->Key->Crypto->BlockSize) != 0)
	{
		// Not an integral multiple of block size
		return NULL;
	}

	if (size > sizeof(tmp1600))
	{
		tmp = Malloc(size);
	}
	else
	{
		tmp = tmp1600;
		no_free = true;
	}

	IkeCryptoEncrypt(cparam->Key, tmp, data, size, cparam->Iv);

	if (size >= cparam->Key->Crypto->BlockSize)
	{
		Copy(cparam->NextIv, ((UCHAR *)tmp) + (size - cparam->Key->Crypto->BlockSize), cparam->Key->Crypto->BlockSize);
	}
	else
	{
		Zero(cparam->NextIv, cparam->Key->Crypto->BlockSize);
	}

	b = MemToBuf(tmp, size);

	if (no_free == false)
	{
		Free(tmp);
	}

	return b;
}

// Decryption
BUF *IkeDecrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	void *tmp;
	BUF *b;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (data == NULL || cparam == NULL)
	{
		return NULL;
	}

	if ((size % cparam->Key->Crypto->BlockSize) != 0)
	{
		// Not an integral multiple of block size
		return NULL;
	}

	if (size > sizeof(tmp1600))
	{
		tmp = Malloc(size);
	}
	else
	{
		tmp = tmp1600;
		no_free = true;
	}

	IkeCryptoDecrypt(cparam->Key, tmp, data, size, cparam->Iv);

	if (size >= cparam->Key->Crypto->BlockSize)
	{
		Copy(cparam->NextIv, ((UCHAR *)data) + (size - cparam->Key->Crypto->BlockSize), cparam->Key->Crypto->BlockSize);
	}
	else
	{
		Zero(cparam->NextIv, cparam->Key->Crypto->BlockSize);
	}

	b = MemToBuf(tmp, size);

	if (no_free == false)
	{
		Free(tmp);
	}

	return b;
}

// Release the IKE packet
void IkeFree(IKE_PACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->PayloadList != NULL)
	{
		IkeFreePayloadList(p->PayloadList);
	}

	if (p->DecryptedPayload != NULL)
	{
		FreeBuf(p->DecryptedPayload);
	}

	Free(p);
}

// Create an IKE packet
IKE_PACKET *IkeNew(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type,
				   bool encrypted, bool commit, bool auth_only, UINT msg_id,
				   LIST *payload_list)
{
	IKE_PACKET *p = ZeroMalloc(sizeof(IKE_PACKET));

	p->InitiatorCookie = init_cookie;
	p->ResponderCookie = resp_cookie;
	p->ExchangeType = exchange_type;
	p->FlagEncrypted = encrypted;
	p->FlagCommit = commit;
	p->FlagAuthOnly = auth_only;
	p->MessageId = msg_id;
	p->PayloadList = payload_list;

	return p;
}

// Create an encryption engine for IKE
IKE_ENGINE *NewIkeEngine()
{
	IKE_ENGINE *e = ZeroMalloc(sizeof(IKE_ENGINE));
	IKE_CRYPTO *des, *des3, *aes;
	IKE_HASH *sha1, *md5, *sha2_256, *sha2_384, *sha2_512;
	IKE_DH *dh1, *dh2, *dh5, *dh2048, *dh3072, *dh4096;
	UINT des_key_sizes[] =
	{
		8,
	};
	UINT des3_key_sizes[] =
	{
		24,
	};
	UINT aes_key_sizes[] =
	{
		16, 24, 32,
	};

	e->CryptosList = NewListFast(NULL);
	e->HashesList = NewListFast(NULL);
	e->DhsList = NewListFast(NULL);

	//// Encryption algorithm
	// DES
	des = NewIkeCrypto(e, IKE_CRYPTO_DES_ID, IKE_CRYPTO_DES_STRING,
		des_key_sizes, sizeof(des_key_sizes) / sizeof(UINT), 8);

	// 3DES
	des3 = NewIkeCrypto(e, IKE_CRYPTO_3DES_ID, IKE_CRYPTO_3DES_STRING,
		des3_key_sizes, sizeof(des3_key_sizes) / sizeof(UINT), 8);

	// AES
	aes = NewIkeCrypto(e, IKE_CRYPTO_AES_ID, IKE_CRYPTO_AES_STRING,
		aes_key_sizes, sizeof(aes_key_sizes) / sizeof(UINT), 16);

	//// Hash algorithm
	// SHA-1
	sha1 = NewIkeHash(e, IKE_HASH_SHA1_ID, IKE_HASH_SHA1_STRING, 20);

	// SHA-2
	// sha2-256
	sha2_256 = NewIkeHash(e, IKE_HASH_SHA2_256_ID, IKE_HASH_SHA2_256_STRING, 32);
	// sha2-384
	sha2_384 = NewIkeHash(e, IKE_HASH_SHA2_384_ID, IKE_HASH_SHA2_384_STRING, 48);
	// sha2-512
	sha2_512 = NewIkeHash(e, IKE_HASH_SHA2_512_ID, IKE_HASH_SHA2_512_STRING, 64);

	// MD5
	md5 = NewIkeHash(e, IKE_HASH_MD5_ID, IKE_HASH_MD5_STRING, 16);

	//// DH algorithm
	dh1 = NewIkeDh(e, IKE_DH_1_ID, IKE_DH_1_STRING, 96);
	dh2 = NewIkeDh(e, IKE_DH_2_ID, IKE_DH_2_STRING, 128);
	dh5 = NewIkeDh(e, IKE_DH_5_ID, IKE_DH_5_STRING, 192);
	dh2048 = NewIkeDh(e, IKE_DH_2048_ID, IKE_DH_2048_STRING, 256);
	dh3072 = NewIkeDh(e, IKE_DH_3072_ID, IKE_DH_3072_STRING, 384);
	dh4096 = NewIkeDh(e, IKE_DH_4096_ID, IKE_DH_4096_STRING, 512);

	// Define the IKE algorithm
	e->IkeCryptos[IKE_P1_CRYPTO_DES_CBC] = des;
	e->IkeCryptos[IKE_P1_CRYPTO_3DES_CBC] = des3;
	e->IkeCryptos[IKE_P1_CRYPTO_AES_CBC] = aes;
	e->IkeHashes[IKE_P1_HASH_MD5] = md5;
	e->IkeHashes[IKE_P1_HASH_SHA1] = sha1;
	e->IkeHashes[IKE_P1_HASH_SHA2_256] = sha2_256;
	e->IkeHashes[IKE_P1_HASH_SHA2_384] = sha2_384;
	e->IkeHashes[IKE_P1_HASH_SHA2_512] = sha2_512;


	// Definition of ESP algorithm
	e->EspCryptos[IKE_TRANSFORM_ID_P2_ESP_DES] = des;
	e->EspCryptos[IKE_TRANSFORM_ID_P2_ESP_3DES] = des3;
	e->EspCryptos[IKE_TRANSFORM_ID_P2_ESP_AES] = aes;
	e->EspHashes[IKE_P2_HMAC_MD5_96] = md5;
	e->EspHashes[IKE_P2_HMAC_SHA1_96] = sha1;
	// IKEv2 integrity algorithm for ESP: AUTH_HMAC_SHA2_256_128 (12)
	e->EspHashes[IKEV2_AUTH_HMAC_SHA2_256_128] = sha2_256;

	// Definition of the DH algorithm
	e->IkeDhs[IKE_P1_DH_GROUP_768_MODP] = e->EspDhs[IKE_P2_DH_GROUP_768_MODP] = dh1;
	e->IkeDhs[IKE_P1_DH_GROUP_1024_MODP] = e->EspDhs[IKE_P2_DH_GROUP_1024_MODP] = dh2;
	e->IkeDhs[IKE_P1_DH_GROUP_1536_MODP] = e->EspDhs[IKE_P2_DH_GROUP_1536_MODP] = dh5;
	e->IkeDhs[IKE_P1_DH_GROUP_2048_MODP] = e->EspDhs[IKE_P2_DH_GROUP_2048_MODP] = dh2048;
	e->IkeDhs[IKE_P1_DH_GROUP_3072_MODP] = e->EspDhs[IKE_P2_DH_GROUP_3072_MODP] = dh3072;
	e->IkeDhs[IKE_P1_DH_GROUP_4096_MODP] = e->EspDhs[IKE_P2_DH_GROUP_4096_MODP] = dh4096;

	return e;
}

// Release the encryption engine for IKE
void FreeIkeEngine(IKE_ENGINE *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(e->CryptosList);i++)
	{
		IKE_CRYPTO *c = LIST_DATA(e->CryptosList, i);

		FreeIkeCrypto(c);
	}

	ReleaseList(e->CryptosList);

	for (i = 0;i < LIST_NUM(e->HashesList);i++)
	{
		IKE_HASH *h = LIST_DATA(e->HashesList, i);

		FreeIkeHash(h);
	}
	ReleaseList(e->HashesList);

	for (i = 0;i < LIST_NUM(e->DhsList);i++)
	{
		IKE_DH *d = LIST_DATA(e->DhsList, i);

		FreeIkeDh(d);
	}
	ReleaseList(e->DhsList);

	Free(e);
}

// Definition of a new DH algorithm for IKE
IKE_DH *NewIkeDh(IKE_ENGINE *e, UINT dh_id, char *name, UINT key_size)
{
	IKE_DH *d;
	// Validate arguments
	if (e == NULL || name == NULL || key_size == 0)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(IKE_DH));

	d->DhId = dh_id;
	d->Name = name;
	d->KeySize = key_size;

	Add(e->DhsList, d);

	return d;
}

// Definition of a new encryption algorithm for IKE
IKE_CRYPTO *NewIkeCrypto(IKE_ENGINE *e, UINT crypto_id, char *name, UINT *key_sizes, UINT num_key_sizes, UINT block_size)
{
	IKE_CRYPTO *c;
	UINT i;
	// Validate arguments
	if (e == NULL || name == NULL || key_sizes == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(IKE_CRYPTO));

	c->CryptoId = crypto_id;
	c->Name = name;

	for (i = 0;i < MIN(num_key_sizes, 16);i++)
	{
		c->KeySizes[i] = key_sizes[i];
	}

	if (num_key_sizes >= 2)
	{
		c->VariableKeySize = true;
	}

	c->BlockSize = block_size;

	Add(e->CryptosList, c);

	return c;
}

// Release the definition of Encryption algorithm for IKE
void FreeIkeCrypto(IKE_CRYPTO *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Free(c);
}

// Release the definition of IKE hash algorithm
void FreeIkeHash(IKE_HASH *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	Free(h);
}

// Release the definition of the DH algorithm for IKE
void FreeIkeDh(IKE_DH *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	Free(d);
}

// Definition of a new hash algorithm for IKE
IKE_HASH *NewIkeHash(IKE_ENGINE *e, UINT hash_id, char *name, UINT size)
{
	IKE_HASH *h;
	// Validate arguments
	if (e == NULL || name == NULL || size == 0)
	{
		return NULL;
	}

	h = ZeroMalloc(sizeof(IKE_HASH));

	h->HashId = hash_id;
	h->Name = name;
	h->HashSize = size;

	Add(e->HashesList, h);

	return h;
}

// Get the encryption algorithm that is used in IKE
IKE_CRYPTO *GetIkeCrypto(IKE_ENGINE *e, bool for_esp, UINT i)
{
	// Validate arguments
	if (e == NULL || i == 0 || i >= MAX_IKE_ENGINE_ELEMENTS)
	{
		return NULL;
	}

	if (for_esp)
	{
		return e->EspCryptos[i];
	}
	else
	{
		return e->IkeCryptos[i];
	}
}

// Get the hash algorithm used in the IKE
IKE_HASH *GetIkeHash(IKE_ENGINE *e, bool for_esp, UINT i)
{
	// Validate arguments
	if (e == NULL || i == 0 || i >= MAX_IKE_ENGINE_ELEMENTS)
	{
		return NULL;
	}

	if (for_esp)
	{
		return e->EspHashes[i];
	}
	else
	{
		return e->IkeHashes[i];
	}
}

// Get the DH algorithm used in the IKE
IKE_DH *GetIkeDh(IKE_ENGINE *e, bool for_esp, UINT i)
{
	// Validate arguments
	if (e == NULL || i == 0 || i >= MAX_IKE_ENGINE_ELEMENTS)
	{
		return NULL;
	}

	if (for_esp)
	{
		return e->EspDhs[i];
	}
	else
	{
		return e->IkeDhs[i];
	}
}

// Perform encryption
void IkeCryptoEncrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec)
{
	// Validate arguments
	if (k == NULL || dst == NULL || src == NULL || size == 0 || ivec == NULL)
	{
		Zero(dst, size);
		return;
	}

	if ((size % k->Crypto->BlockSize) != 0)
	{
		Zero(dst, size);
		return;
	}

	switch (k->Crypto->CryptoId)
	{
	case IKE_CRYPTO_DES_ID:		// DES
		DesEncrypt(dst, src, size, k->DesKey1, ivec);
		break;

	case IKE_CRYPTO_3DES_ID:	// 3DES
		Des3Encrypt2(dst, src, size, k->DesKey1, k->DesKey2, k->DesKey3, ivec);
		break;

	case IKE_CRYPTO_AES_ID:		// AES
		AesEncrypt(dst, src, size, k->AesKey, ivec);
		break;

	default:
		// Unknown
		Zero(dst, size);
		break;
	}
}

// Perform decryption
void IkeCryptoDecrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec)
{
	// Validate arguments
	if (k == NULL || dst == NULL || src == NULL || size == 0 || ivec == NULL)
	{
		Zero(dst, size);
		return;
	}

	if ((size % k->Crypto->BlockSize) != 0)
	{
		Zero(dst, size);
		return;
	}

	switch (k->Crypto->CryptoId)
	{
	case IKE_CRYPTO_DES_ID:		// DES
		DesDecrypt(dst, src, size, k->DesKey1, ivec);
		break;

	case IKE_CRYPTO_3DES_ID:	// 3DES
		Des3Decrypt2(dst, src, size, k->DesKey1, k->DesKey2, k->DesKey3, ivec);
		break;

	case IKE_CRYPTO_AES_ID:		// AES
		AesDecrypt(dst, src, size, k->AesKey, ivec);
		break;

	default:
		// Unknown
		Zero(dst, size);
		break;
	}
}

// Calculate a hash
void IkeHash(IKE_HASH *h, void *dst, void *src, UINT size)
{
	// Validate arguments
	if (h == NULL || dst == NULL || (size != 0 && src == NULL))
	{
		Zero(dst, size);
		return;
	}

	switch (h->HashId)
	{
	case IKE_HASH_MD5_ID:
		// MD5
		Md5(dst, src, size);
		break;

	case IKE_HASH_SHA1_ID:
		// SHA-1
		Sha1(dst, src, size);
		break;
	case IKE_HASH_SHA2_256_ID:
		Sha2_256(dst, src, size);
		break;
	case IKE_HASH_SHA2_384_ID:
		Sha2_384(dst, src, size);
		break;
	case IKE_HASH_SHA2_512_ID:
		Sha2_512(dst, src, size);
		break;

	default:
		// Unknown
		Zero(dst, size);
		break;
	}
}

// Calculation of HMAC
void IkeHMac(IKE_HASH *h, void *dst, void *key, UINT key_size, void *data, UINT data_size)
{
	MD *md = NULL;

	switch (h->HashId)
	{
	case IKE_HASH_MD5_ID:
		md = NewMd("MD5");
		break;
	case IKE_HASH_SHA1_ID:
		md = NewMd("SHA1");
		break;
	case IKE_HASH_SHA2_256_ID:
		md = NewMd("SHA256");
		break;
	case IKE_HASH_SHA2_384_ID:
		md = NewMd("SHA384");
		break;
	case IKE_HASH_SHA2_512_ID:
		md = NewMd("SHA512");
		break;
	}

	if (md == NULL)
	{
		Debug("IkeHMac(): The MD object is NULL! Either NewMd() failed or the current algorithm is not handled by the switch-case block.\n");
		return;
	}

	if (SetMdKey(md, key, key_size) == false)
	{
		Debug("IkeHMac(): SetMdKey() failed!\n");
		goto cleanup;
	}

	if (MdProcess(md, dst, data, data_size) == 0)
	{
		Debug("IkeHMac(): MdProcess() returned 0!\n");
	}

cleanup:
	FreeMd(md);
}

void IkeHMacBuf(IKE_HASH *h, void *dst, BUF *key, BUF *data)
{
	// Validate arguments
	if (h == NULL || dst == NULL || key == NULL || data == NULL)
	{
		return;
	}

	IkeHMac(h, dst, key->Buf, key->Size, data->Buf, data->Size);
}

// Check whether the key size is valid
bool IkeCheckKeySize(IKE_CRYPTO *c, UINT size)
{
	bool ok = false;
	UINT i;
	// Validate arguments
	if (c == NULL || size == 0)
	{
		return false;
	}

	for (i = 0;i < sizeof(c->KeySizes) / sizeof(UINT);i++)
	{
		if (c->KeySizes[i] == size)
		{
			ok = true;
			break;
		}
	}

	return ok;
}

// Create a key
IKE_CRYPTO_KEY *IkeNewKey(IKE_CRYPTO *c, void *data, UINT size)
{
	IKE_CRYPTO_KEY *k;
	// Validate arguments
	if (c == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	if (IkeCheckKeySize(c, size) == false)
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(IKE_CRYPTO_KEY));
	k->Crypto = c;
	k->Data = Clone(data, size);
	k->Size = size;

	switch (k->Crypto->CryptoId)
	{
	case IKE_CRYPTO_DES_ID:
		// DES 64bit key
		k->DesKey1 = DesNewKeyValue(data);
		break;

	case IKE_CRYPTO_3DES_ID:
		// 3DES 192bit key
		k->DesKey1 = DesNewKeyValue(((UCHAR *)data) + DES_KEY_SIZE * 0);
		k->DesKey2 = DesNewKeyValue(((UCHAR *)data) + DES_KEY_SIZE * 1);
		k->DesKey3 = DesNewKeyValue(((UCHAR *)data) + DES_KEY_SIZE * 2);
		break;

	case IKE_CRYPTO_AES_ID:
		// AES variable length key
		k->AesKey = AesNewKey(data, size);
		break;
	}

	return k;
}

// Release the key
void IkeFreeKey(IKE_CRYPTO_KEY *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	DesFreeKeyValue(k->DesKey1);
	DesFreeKeyValue(k->DesKey2);
	DesFreeKeyValue(k->DesKey3);

	AesFreeKey(k->AesKey);

	Free(k->Data);

	Free(k);
}

// Create a DH object
DH_CTX *IkeDhNewCtx(IKE_DH *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return NULL;
	}

	switch (d->DhId)
	{
	case IKE_DH_1_ID:
		return DhNewGroup1();

	case IKE_DH_2_ID:
		return DhNewGroup2();

	case IKE_DH_5_ID:
		return DhNewGroup5();

	case IKE_DH_2048_ID:
		return DhNew2048();

	case IKE_DH_3072_ID:
		return DhNew3072();

	case IKE_DH_4096_ID:
		return DhNew4096();
	}

	return NULL;
}

// Release the DH object
void IkeDhFreeCtx(DH_CTX *dh)
{
	// Validate arguments
	if (dh == NULL)
	{
		return;
	}

	DhFree(dh);
}

// IKEV2 functions

// Internal helper function prototypes (IKEv2)
void IkeV2FreeTransformList(LIST *o);
void IkeV2FreeTransformAttribute(IKEV2_TRANSFORM_ATTRIBUTE *a);
BUF *IkeV2BuildTransformAttributeList(LIST *o);
BUF *IkeV2BuildTs(IKEV2_TS *ts);

// Read a big-endian 16-bit value
static USHORT IkeV2ReadU16(UCHAR *p)
{
	return (USHORT)(((USHORT)p[0] << 8) | (USHORT)p[1]);
}

// Write a big-endian 16-bit value
static void IkeV2WriteU16(UCHAR *p, USHORT v)
{
	p[0] = (UCHAR)((v >> 8) & 0xff);
	p[1] = (UCHAR)(v & 0xff);
}

// Create a new IKEv2 packet
IKE_PACKET *IkeV2New(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type,
					 UINT msg_id, bool initiator, bool response, LIST *payload_list)
{
	IKE_PACKET *p = IkeNew(init_cookie, resp_cookie, exchange_type, false, false, false,
		msg_id, payload_list);

	if (p == NULL)
	{
		return NULL;
	}

	p->MajorVersion = IKE_MAJOR_VERSION_2;
	p->FlagV2Initiator = initiator;
	p->FlagV2Response = response;

	return p;
}

//// SA payload (IKEv2)

// Parse the IKEv2 SA payload
bool IkeV2ParseSaPayload(IKEV2_PACKET_SA_PAYLOAD *t, BUF *b)
{
	LIST *proposal_list;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	proposal_list = NewListFast(NULL);

	while (true)
	{
		UCHAR ph[8];
		UCHAR next_sub, proposal_num, protocol_id, spi_size;
		UINT num_transforms;
		USHORT proposal_length;
		UINT transform_bytes;
		IKEV2_PROPOSAL *proposal;
		BUF *spi = NULL;
		LIST *transform_list;
		UINT i;
		bool error = false;

		// Proposal substructure header:
		//   NextSubstructure(1) Reserved(1) ProposalLength(2)
		//   ProposalNum(1) ProtocolId(1) SpiSize(1) NumTransforms(1)
		if (ReadBuf(b, ph, sizeof(ph)) != sizeof(ph))
		{
			break;
		}

		next_sub = ph[0];
		proposal_length = IkeV2ReadU16(ph + 2);
		proposal_num = ph[4];
		protocol_id = ph[5];
		spi_size = ph[6];
		num_transforms = ph[7];

		if (proposal_length < sizeof(ph) || spi_size > 16)
		{
			break;
		}

		// Number of bytes occupied by the transforms of this proposal
		transform_bytes = (UINT)proposal_length - sizeof(ph) - spi_size;

		if (b->Size - b->Current < transform_bytes)
		{
			break;
		}

		if (spi_size > 0)
		{
			spi = ReadBufFromBuf(b, spi_size);
			if (spi == NULL)
			{
				error = true;
			}
		}

		transform_list = NewListFast(NULL);

		// Transform substructures:
		//   NextSubstructure(1) Reserved(1) TransformLength(2) TransformType(1)
		//   Reserved(1) TransformId(2) Attributes...
		for (i = 0; error == false && i < num_transforms && transform_bytes >= 8; i++)
		{
			UCHAR th[8];
			USHORT transform_length;
			IKEV2_TRANSFORM *transform;
			BUF *attr_data;
			UINT num_attrs, pos;

			if (ReadBuf(b, th, sizeof(th)) != sizeof(th))
			{
				error = true;
				break;
			}

			transform_length = IkeV2ReadU16(th + 2);

			if (transform_length < sizeof(th) || transform_length > transform_bytes)
			{
				error = true;
				break;
			}

			attr_data = ReadBufFromBuf(b, transform_length - sizeof(th));
			if (attr_data == NULL)
			{
				error = true;
				break;
			}

			transform_bytes -= transform_length;

			transform = ZeroMalloc(sizeof(IKEV2_TRANSFORM));
			transform->TransformType = th[4];
			transform->TransformId = IkeV2ReadU16(th + 6);
			transform->AttributeList = NewListFast(NULL);

			// Attributes: [AF(1bit) | Type(15bits)](2)
			//   TV form: Value(2)     TLV form: Length(2) Value(...)
			num_attrs = attr_data->Size;
			pos = 0;
			while (num_attrs - pos >= 4)
			{
				UCHAR *ap = ((UCHAR *)attr_data->Buf) + pos;
				USHORT raw = IkeV2ReadU16(ap);
				bool is_tv = (raw & 0x8000) ? true : false;
				UINT attr_type = raw & 0x7fff;

				if (is_tv)
				{
					Add(transform->AttributeList, IkeV2NewTransformAttributeTv(attr_type, IkeV2ReadU16(ap + 2)));
					pos += 4;
				}
				else
				{
					USHORT value_length = IkeV2ReadU16(ap + 2);
					pos += 4;
					if (value_length > num_attrs - pos)
					{
						break;
					}
					Add(transform->AttributeList, IkeV2NewTransformAttributeTlv(attr_type, ap + pos, value_length));
					pos += value_length;
				}
			}

			FreeBuf(attr_data);

			Add(transform_list, transform);
		}

		if (error == false && transform_bytes > 0)
		{
			// Skip any trailing bytes of the proposal not covered by the
			// transform count to stay aligned with the next substructure
			BUF *rest = ReadBufFromBuf(b, transform_bytes);
			if (rest != NULL)
			{
				FreeBuf(rest);
			}
			else
			{
				error = true;
			}
		}

		if (error)
		{
			if (spi != NULL)
			{
				FreeBuf(spi);
			}
			IkeV2FreeTransformList(transform_list);
			break;
		}

		proposal = ZeroMalloc(sizeof(IKEV2_PROPOSAL));
		proposal->Number = proposal_num;
		proposal->ProtocolId = protocol_id;
		proposal->Spi = spi;
		proposal->TransformList = transform_list;

		Add(proposal_list, proposal);

		if (next_sub == 0)
		{
			// Last proposal
			break;
		}
	}

	if (LIST_NUM(proposal_list) == 0)
	{
		ReleaseList(proposal_list);
		return false;
	}

	t->ProposalList = proposal_list;

	return true;
}

// Release a list of IKEv2 transforms
void IkeV2FreeTransformList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IKEV2_TRANSFORM *t = LIST_DATA(o, i);
		IkeV2FreeTransform(t);
	}

	ReleaseList(o);
}

// Release the IKEv2 SA payload
void IkeV2FreeSaPayload(IKEV2_PACKET_SA_PAYLOAD *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->ProposalList != NULL)
	{
		for (i = 0; i < LIST_NUM(t->ProposalList); i++)
		{
			IKEV2_PROPOSAL *p = LIST_DATA(t->ProposalList, i);
			IkeV2FreeProposal(p);
		}

		ReleaseList(t->ProposalList);
	}
}

// Release an IKEv2 proposal
void IkeV2FreeProposal(IKEV2_PROPOSAL *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->Spi != NULL)
	{
		FreeBuf(p->Spi);
	}

	IkeV2FreeTransformList(p->TransformList);

	Free(p);
}

// Release an IKEv2 transform
void IkeV2FreeTransform(IKEV2_TRANSFORM *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->AttributeList != NULL)
	{
		for (i = 0; i < LIST_NUM(t->AttributeList); i++)
		{
			IKEV2_TRANSFORM_ATTRIBUTE *a = LIST_DATA(t->AttributeList, i);
			IkeV2FreeTransformAttribute(a);
		}

		ReleaseList(t->AttributeList);
	}

	Free(t);
}

// Release an IKEv2 transform attribute
void IkeV2FreeTransformAttribute(IKEV2_TRANSFORM_ATTRIBUTE *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->Value != NULL)
	{
		FreeBuf(a->Value);
	}

	Free(a);
}

// Build the IKEv2 SA payload
BUF *IkeV2BuildSaPayload(IKEV2_PACKET_SA_PAYLOAD *t)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0; i < LIST_NUM(t->ProposalList); i++)
	{
		IKEV2_PROPOSAL *p = LIST_DATA(t->ProposalList, i);
		bool is_last = (i == (LIST_NUM(t->ProposalList) - 1)) ? true : false;
		BUF *transform_buf = NewBuf();
		UCHAR ph[8];
		UINT j;

		// Serialize the transforms first: the proposal length field needs
		// their total size
		for (j = 0; j < LIST_NUM(p->TransformList); j++)
		{
			IKEV2_TRANSFORM *tr = LIST_DATA(p->TransformList, j);
			bool tr_is_last = (j == (LIST_NUM(p->TransformList) - 1)) ? true : false;
			BUF *attr_buf = IkeV2BuildTransformAttributeList(tr->AttributeList);
			UCHAR th[8];

			Zero(th, sizeof(th));
			th[0] = tr_is_last ? 0 : 3;	// 0 = last substructure, 3 = another transform follows
			IkeV2WriteU16(th + 2, (USHORT)(sizeof(th) + (attr_buf != NULL ? attr_buf->Size : 0)));
			th[4] = tr->TransformType;
			IkeV2WriteU16(th + 6, tr->TransformId);

			WriteBuf(transform_buf, th, sizeof(th));

			if (attr_buf != NULL)
			{
				WriteBufBuf(transform_buf, attr_buf);
				FreeBuf(attr_buf);
			}
		}

		// Proposal substructure header:
		//   NextSubstructure(1) Reserved(1) ProposalLength(2)
		//   ProposalNum(1) ProtocolId(1) SpiSize(1) NumTransforms(1)
		Zero(ph, sizeof(ph));
		ph[0] = is_last ? 0 : 2;		// 0 = last substructure, 2 = another proposal follows
		IkeV2WriteU16(ph + 2, (USHORT)(sizeof(ph) + (p->Spi != NULL ? p->Spi->Size : 0) + transform_buf->Size));
		ph[4] = p->Number;
		ph[5] = p->ProtocolId;
		ph[6] = p->Spi != NULL ? (UCHAR)p->Spi->Size : 0;
		ph[7] = (UCHAR)LIST_NUM(p->TransformList);

		WriteBuf(b, ph, sizeof(ph));

		if (p->Spi != NULL && p->Spi->Size > 0)
		{
			WriteBufBuf(b, p->Spi);
		}

		WriteBufBuf(b, transform_buf);

		FreeBuf(transform_buf);
	}

	return b;
}

// Build a list of IKEv2 transform attributes
BUF *IkeV2BuildTransformAttributeList(LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IKEV2_TRANSFORM_ATTRIBUTE *a = LIST_DATA(o, i);
		UCHAR ah[4];

		if (a->IsTv)
		{
			IkeV2WriteU16(ah, (USHORT)(0x8000 | a->Type));
			IkeV2WriteU16(ah + 2, a->Value16);
			WriteBuf(b, ah, sizeof(ah));
		}
		else
		{
			IkeV2WriteU16(ah, (USHORT)a->Type);
			IkeV2WriteU16(ah + 2, (USHORT)(a->Value != NULL ? a->Value->Size : 0));
			WriteBuf(b, ah, sizeof(ah));
			if (a->Value != NULL && a->Value->Size > 0)
			{
				WriteBufBuf(b, a->Value);
			}
		}
	}

	return b;
}

// Create a new IKEv2 SA payload
IKE_PACKET_PAYLOAD *IkeV2NewSaPayload(LIST *proposal_list)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (proposal_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKEV2_PAYLOAD_SA);
	p->Payload.SaV2.ProposalList = proposal_list;

	return p;
}

// Create a new IKEv2 proposal
IKEV2_PROPOSAL *IkeV2NewProposal(UCHAR number, UCHAR protocol_id, void *spi, UINT spi_size, LIST *transform_list)
{
	IKEV2_PROPOSAL *p;
	// Validate arguments
	if (transform_list == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(IKEV2_PROPOSAL));
	p->Number = number;
	p->ProtocolId = protocol_id;
	if (spi != NULL && spi_size > 0)
	{
		p->Spi = MemToBuf(spi, spi_size);
	}
	p->TransformList = transform_list;

	return p;
}

// Create a new IKEv2 transform without attributes
IKEV2_TRANSFORM *IkeV2NewTransform(UCHAR transform_type, USHORT transform_id)
{
	IKEV2_TRANSFORM *t = ZeroMalloc(sizeof(IKEV2_TRANSFORM));
	t->TransformType = transform_type;
	t->TransformId = transform_id;
	t->AttributeList = NewListFast(NULL);
	return t;
}

// Create a new IKEv2 transform with a single TLV attribute
IKEV2_TRANSFORM *IkeV2NewTransformTlv(UCHAR transform_type, USHORT transform_id, UINT attr_type, void *attr_value, UINT attr_size)
{
	IKEV2_TRANSFORM *t = IkeV2NewTransform(transform_type, transform_id);
	Add(t->AttributeList, IkeV2NewTransformAttributeTlv(attr_type, attr_value, attr_size));
	return t;
}

// Create a new TV-formatted IKEv2 transform attribute
IKEV2_TRANSFORM_ATTRIBUTE *IkeV2NewTransformAttributeTv(UINT type, USHORT value)
{
	IKEV2_TRANSFORM_ATTRIBUTE *a = ZeroMalloc(sizeof(IKEV2_TRANSFORM_ATTRIBUTE));
	a->IsTv = true;
	a->Type = type;
	a->Value16 = value;
	return a;
}

// Create a new TLV-formatted IKEv2 transform attribute
IKEV2_TRANSFORM_ATTRIBUTE *IkeV2NewTransformAttributeTlv(UINT type, void *value, UINT size)
{
	IKEV2_TRANSFORM_ATTRIBUTE *a = ZeroMalloc(sizeof(IKEV2_TRANSFORM_ATTRIBUTE));
	a->IsTv = false;
	a->Type = type;
	a->Value = value != NULL ? MemToBuf(value, size) : NULL;
	return a;
}

// Get the number of transforms of the specified type in an IKEv2 proposal
UINT IkeV2GetTransformIdNum(IKEV2_PROPOSAL *p, UCHAR transform_type)
{
	UINT i, num = 0;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	for (i = 0; i < LIST_NUM(p->TransformList); i++)
	{
		IKEV2_TRANSFORM *t = LIST_DATA(p->TransformList, i);
		if (t->TransformType == transform_type)
		{
			num++;
		}
	}

	return num;
}

// Get the transform ID of the specified type and index in an IKEv2 proposal
UINT IkeV2GetTransformId(IKEV2_PROPOSAL *p, UCHAR transform_type, UINT index)
{
	UINT i, num = 0;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	for (i = 0; i < LIST_NUM(p->TransformList); i++)
	{
		IKEV2_TRANSFORM *t = LIST_DATA(p->TransformList, i);
		if (t->TransformType == transform_type)
		{
			if (num == index)
			{
				return t->TransformId;
			}
			num++;
		}
	}

	return 0;
}

// Get the key length attribute (in bits) of the encryption transforms of an IKEv2 proposal
USHORT IkeV2GetKeyLengthBit(IKEV2_PROPOSAL *p)
{
	UINT i, j;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	for (i = 0; i < LIST_NUM(p->TransformList); i++)
	{
		IKEV2_TRANSFORM *t = LIST_DATA(p->TransformList, i);
		if (t->TransformType == IKEV2_TRANSFORM_TYPE_ENCR)
		{
			for (j = 0; j < LIST_NUM(t->AttributeList); j++)
			{
				IKEV2_TRANSFORM_ATTRIBUTE *a = LIST_DATA(t->AttributeList, j);
				if (a->IsTv && a->Type == IKEV2_SA_ATTR_KEY_LENGTH)
				{
					return a->Value16;
				}
			}
		}
	}

	return 0;
}

//// Notification payload (IKEv2)

// Parse the IKEv2 notification payload
bool IkeV2ParseNotifyPayload(IKE_PACKET_NOTICE_PAYLOAD *t, BUF *b)
{
	UCHAR nh[4];
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	// ProtocolId(1) SpiSize(1) NotifyMessageType(2)
	if (ReadBuf(b, nh, sizeof(nh)) != sizeof(nh))
	{
		return false;
	}

	t->ProtocolId = nh[0];
	t->MessageType = IkeV2ReadU16(nh + 2);

	if (nh[1] > 0)
	{
		t->Spi = ReadBufFromBuf(b, nh[1]);
		if (t->Spi == NULL)
		{
			return false;
		}
	}

	t->MessageData = ReadRemainBuf(b);

	return true;
}

// Build the IKEv2 notification payload
BUF *IkeV2BuildNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t)
{
	BUF *b;
	UCHAR nh[4];
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(nh, sizeof(nh));
	nh[0] = t->ProtocolId;
	nh[1] = t->Spi != NULL ? (UCHAR)t->Spi->Size : 0;
	IkeV2WriteU16(nh + 2, t->MessageType);

	b = NewBuf();
	WriteBuf(b, nh, sizeof(nh));

	if (t->Spi != NULL && t->Spi->Size > 0)
	{
		WriteBufBuf(b, t->Spi);
	}

	if (t->MessageData != NULL && t->MessageData->Size > 0)
	{
		WriteBufBuf(b, t->MessageData);
	}

	return b;
}

// Create a new IKEv2 notification payload
IKE_PACKET_PAYLOAD *IkeV2NewNotifyPayload(UCHAR protocol_id, USHORT message_type,
										  void *spi, UINT spi_size,
										  void *message, UINT message_size)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (spi_size > 255)
	{
		return NULL;
	}

	p = IkeNewPayload(IKEV2_PAYLOAD_NOTIFY);
	p->Payload.Notice.ProtocolId = protocol_id;
	p->Payload.Notice.MessageType = message_type;
	if (spi != NULL && spi_size > 0)
	{
		p->Payload.Notice.Spi = MemToBuf(spi, spi_size);
	}
	if (message != NULL && message_size > 0)
	{
		p->Payload.Notice.MessageData = MemToBuf(message, message_size);
	}

	return p;
}

// Create an IKEv2 error notification payload for the IKE SA
IKE_PACKET_PAYLOAD *IkeV2NewNoticeErrorPayload(USHORT message_type, UINT64 init_cookie, UINT64 resp_cookie)
{
	// For notifications that concern the IKE SA itself, the Protocol ID and
	// the SPI size must be zero (RFC 7296 section 3.10, errata ID 6940)
	return IkeV2NewNotifyPayload(0, message_type, NULL, 0, NULL, 0);
}

//// Delete payload (IKEv2)

// Parse the IKEv2 deletion payload
bool IkeV2ParseDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t, BUF *b)
{
	UCHAR dh[4];
	USHORT num_spis;
	UCHAR spi_size;
	UINT i;
	bool ok = true;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	// ProtocolId(1) SpiSize(1) NumSPIs(2)
	if (ReadBuf(b, dh, sizeof(dh)) != sizeof(dh))
	{
		return false;
	}

	t->ProtocolId = dh[0];
	spi_size = dh[1];
	num_spis = IkeV2ReadU16(dh + 2);

	t->SpiList = NewListFast(NULL);

	for (i = 0; i < num_spis; i++)
	{
		BUF *spi = ReadBufFromBuf(b, spi_size);
		if (spi == NULL)
		{
			ok = false;
			break;
		}
		Add(t->SpiList, spi);
	}

	if (ok == false)
	{
		IkeFreeDeletePayload(t);
		return false;
	}

	return true;
}

// Build the IKEv2 deletion payload
BUF *IkeV2BuildDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t)
{
	BUF *b;
	UCHAR dh[4];
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(dh, sizeof(dh));
	dh[0] = t->ProtocolId;
	if (LIST_NUM(t->SpiList) > 0)
	{
		BUF *first = LIST_DATA(t->SpiList, 0);
		dh[1] = (UCHAR)first->Size;
	}
	IkeV2WriteU16(dh + 2, (USHORT)LIST_NUM(t->SpiList));

	b = NewBuf();
	WriteBuf(b, dh, sizeof(dh));

	for (i = 0; i < LIST_NUM(t->SpiList); i++)
	{
		BUF *spi = LIST_DATA(t->SpiList, i);
		WriteBufBuf(b, spi);
	}

	return b;
}

// Create a new IKEv2 deletion payload
IKE_PACKET_PAYLOAD *IkeV2NewDeletePayload(UCHAR protocol_id, LIST *spi_list)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (spi_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKEV2_PAYLOAD_DELETE);
	p->Payload.Delete.ProtocolId = protocol_id;
	p->Payload.Delete.SpiList = spi_list;

	return p;
}

//// Traffic Selector payload (IKEv2)

// Parse the IKEv2 traffic selector payload
bool IkeV2ParseTsPayload(IKEV2_PACKET_TS_PAYLOAD *t, BUF *b)
{
	UCHAR th[4];
	UCHAR num_ts;
	UINT i;
	bool error = false;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	// NumTSs(1) Reserved(3)
	if (ReadBuf(b, th, sizeof(th)) != sizeof(th))
	{
		return false;
	}

	num_ts = th[0];

	t->TsList = NewListFast(NULL);

	for (i = 0; i < num_ts; i++)
	{
		UCHAR sh[4];
		USHORT selector_length;
		IKEV2_TS *ts;

		// TSType(1) IPProtocolID(1) SelectorLength(2)
		if (ReadBuf(b, sh, sizeof(sh)) != sizeof(sh))
		{
			error = true;
			break;
		}

		selector_length = IkeV2ReadU16(sh + 2);

		if (sh[0] != IKEV2_TS_IPV4_ADDR_RANGE && sh[0] != IKEV2_TS_IPV6_ADDR_RANGE)
		{
			error = true;
			break;
		}

		if (sh[0] == IKEV2_TS_IPV4_ADDR_RANGE && selector_length != 16)
		{
			error = true;
			break;
		}

		if (sh[0] == IKEV2_TS_IPV6_ADDR_RANGE && selector_length != 40)
		{
			error = true;
			break;
		}

		ts = ZeroMalloc(sizeof(IKEV2_TS));
		ts->Type = sh[0];
		ts->IpProtocol = sh[1];

		// StartPort(2) EndPort(2)
		{
			UCHAR ph[4];
			if (ReadBuf(b, ph, sizeof(ph)) != sizeof(ph))
			{
				Free(ts);
				error = true;
				break;
			}
			ts->StartPort = IkeV2ReadU16(ph);
			ts->EndPort = IkeV2ReadU16(ph + 2);
		}

		// StartAddress + EndAddress
		{
			UINT addr_size = (ts->Type == IKEV2_TS_IPV4_ADDR_RANGE) ? 4 : 16;
			UCHAR addr[16];

			if (ReadBuf(b, addr, addr_size) != addr_size)
			{
				Free(ts);
				error = true;
				break;
			}

			if (addr_size == 4)
			{
				SetIP(&ts->StartAddress, addr[0], addr[1], addr[2], addr[3]);
			}
			else
			{
				SetIP6(&ts->StartAddress, addr);
			}

			if (ReadBuf(b, addr, addr_size) != addr_size)
			{
				Free(ts);
				error = true;
				break;
			}

			if (addr_size == 4)
			{
				SetIP(&ts->EndAddress, addr[0], addr[1], addr[2], addr[3]);
			}
			else
			{
				SetIP6(&ts->EndAddress, addr);
			}
		}

		Add(t->TsList, ts);
	}

	if (error || LIST_NUM(t->TsList) == 0)
	{
		IkeV2FreeTsPayload(t);
		return false;
	}

	return true;
}

// Release the IKEv2 traffic selector payload
void IkeV2FreeTsPayload(IKEV2_PACKET_TS_PAYLOAD *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->TsList != NULL)
	{
		for (i = 0; i < LIST_NUM(t->TsList); i++)
		{
			IKEV2_TS *ts = LIST_DATA(t->TsList, i);
			IkeV2FreeTs(ts);
		}
		ReleaseList(t->TsList);
	}
}

// Release an IKEv2 traffic selector
void IkeV2FreeTs(IKEV2_TS *ts)
{
	if (ts == NULL)
	{
		return;
	}

	Free(ts);
}

// Build a single IKEv2 traffic selector
BUF *IkeV2BuildTs(IKEV2_TS *ts)
{
	BUF *b;
	UCHAR sh[4];
	UINT addr_size;
	// Validate arguments
	if (ts == NULL)
	{
		return NULL;
	}

	addr_size = (ts->Type == IKEV2_TS_IPV6_ADDR_RANGE) ? 16 : 4;

	b = NewBuf();

	Zero(sh, sizeof(sh));
	sh[0] = ts->Type == IKEV2_TS_IPV6_ADDR_RANGE ? IKEV2_TS_IPV6_ADDR_RANGE : IKEV2_TS_IPV4_ADDR_RANGE;
	sh[1] = ts->IpProtocol;
	IkeV2WriteU16(sh + 2, (USHORT)(4 + 4 + addr_size * 2));
	WriteBuf(b, sh, sizeof(sh));

	{
		UCHAR ph[4];
		IkeV2WriteU16(ph, (USHORT)ts->StartPort);
		IkeV2WriteU16(ph + 2, (USHORT)ts->EndPort);
		WriteBuf(b, ph, sizeof(ph));
	}

	if (addr_size == 4)
	{
		WriteBuf(b, IPV4(ts->StartAddress.address), IPV4_SIZE);
		WriteBuf(b, IPV4(ts->EndAddress.address), IPV4_SIZE);
	}
	else
	{
		WriteBuf(b, ts->StartAddress.address, 16);
		WriteBuf(b, ts->EndAddress.address, 16);
	}

	return b;
}

// Build the IKEv2 traffic selector payload
BUF *IkeV2BuildTsPayload(IKEV2_PACKET_TS_PAYLOAD *t)
{
	BUF *b;
	UCHAR th[4];
	UINT i;
	// Validate arguments
	if (t == NULL || t->TsList == NULL)
	{
		return NULL;
	}

	Zero(th, sizeof(th));
	th[0] = (UCHAR)LIST_NUM(t->TsList);

	b = NewBuf();
	WriteBuf(b, th, sizeof(th));

	for (i = 0; i < LIST_NUM(t->TsList); i++)
	{
		IKEV2_TS *ts = LIST_DATA(t->TsList, i);
		BUF *ts_buf = IkeV2BuildTs(ts);
		WriteBufBuf(b, ts_buf);
		FreeBuf(ts_buf);
	}

	return b;
}

// Create a new IKEv2 traffic selector payload
IKE_PACKET_PAYLOAD *IkeV2NewTsPayload(UCHAR payload_type, LIST *ts_list)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (ts_list == NULL || (payload_type != IKEV2_PAYLOAD_TS_INITIATOR && payload_type != IKEV2_PAYLOAD_TS_RESPONDER))
	{
		return NULL;
	}

	p = IkeNewPayload(payload_type);
	p->Payload.TsV2.TsList = ts_list;

	return p;
}

// Create a traffic selector that covers everything
IKEV2_TS *IkeV2NewTsAny(bool is_ipv6)
{
	IKEV2_TS *ts = ZeroMalloc(sizeof(IKEV2_TS));
	UCHAR any4[4] = {0, 0, 0, 0};
	UCHAR any6[16];
	UCHAR all4[4] = {255, 255, 255, 255};

	Zero(any6, sizeof(any6));

	ts->Type = is_ipv6 ? IKEV2_TS_IPV6_ADDR_RANGE : IKEV2_TS_IPV4_ADDR_RANGE;
	ts->IpProtocol = 0;
	ts->StartPort = 0;
	ts->EndPort = 65535;

	if (is_ipv6 == false)
	{
		SetIP(&ts->StartAddress, any4[0], any4[1], any4[2], any4[3]);
		SetIP(&ts->EndAddress, all4[0], all4[1], all4[2], all4[3]);
	}
	else
	{
		SetIP6(&ts->StartAddress, any6);
		// The IPv6 "any" range ends with all bits set
		Zero(any6, sizeof(any6));
		SetIP6(&ts->EndAddress, any6);
		ts->EndAddress.address[15] = 0xff;
	}

	return ts;
}

//// Configuration payload (IKEv2)

// Parse the IKEv2 configuration payload
bool IkeV2ParseCpPayload(IKEV2_PACKET_CP_PAYLOAD *t, BUF *b)
{
	UCHAR ch[4];
	UINT size, pos;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	// CFGType(1) Reserved(3)
	if (ReadBuf(b, ch, sizeof(ch)) != sizeof(ch))
	{
		return false;
	}

	t->Type = ch[0];
	t->AttributeList = NewListFast(NULL);

	// Attributes: [R(1bit) | Type(15bits)](2) Length(2) Value(...)
	size = b->Size - b->Current;
	pos = b->Current;

	while (size - pos >= 4)
	{
		UCHAR *ap = ((UCHAR *)b->Buf) + pos;
		USHORT raw = IkeV2ReadU16(ap);
		UINT attr_type = raw & 0x7fff;
		USHORT value_length = IkeV2ReadU16(ap + 2);

		pos += 4;
		if (value_length > size - pos)
		{
			break;
		}

		Add(t->AttributeList, IkeV2NewCpAttribute(attr_type, ap + pos, value_length));
		pos += value_length;
	}

	return true;
}

// Release the IKEv2 configuration payload
void IkeV2FreeCpPayload(IKEV2_PACKET_CP_PAYLOAD *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->AttributeList != NULL)
	{
		for (i = 0; i < LIST_NUM(t->AttributeList); i++)
		{
			IKEV2_CP_ATTRIBUTE *a = LIST_DATA(t->AttributeList, i);
			IkeV2FreeCpAttribute(a);
		}
		ReleaseList(t->AttributeList);
	}
}

// Release an IKEv2 configuration attribute
void IkeV2FreeCpAttribute(IKEV2_CP_ATTRIBUTE *a)
{
	if (a == NULL)
	{
		return;
	}

	if (a->Value != NULL)
	{
		FreeBuf(a->Value);
	}

	Free(a);
}

// Build the IKEv2 configuration payload
BUF *IkeV2BuildCpPayload(IKEV2_PACKET_CP_PAYLOAD *t)
{
	BUF *b;
	UCHAR ch[4];
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(ch, sizeof(ch));
	ch[0] = t->Type;

	b = NewBuf();
	WriteBuf(b, ch, sizeof(ch));

	for (i = 0; i < LIST_NUM(t->AttributeList); i++)
	{
		IKEV2_CP_ATTRIBUTE *a = LIST_DATA(t->AttributeList, i);
		UCHAR ah[4];

		// In IKEv2 the highest attribute bit is reserved and the length
		// field always carries the value length (RFC 7296 section 3.15)
		IkeV2WriteU16(ah, (USHORT)a->Type);
		IkeV2WriteU16(ah + 2, (USHORT)(a->Value != NULL ? a->Value->Size : 0));

		WriteBuf(b, ah, sizeof(ah));

		if (a->Value != NULL && a->Value->Size > 0)
		{
			WriteBufBuf(b, a->Value);
		}
	}

	return b;
}

// Create a new IKEv2 configuration payload
IKE_PACKET_PAYLOAD *IkeV2NewCpPayload(UCHAR type, LIST *attr_list)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (attr_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKEV2_PAYLOAD_CONFIGURATION);
	p->Payload.CpV2.Type = type;
	p->Payload.CpV2.AttributeList = attr_list;

	return p;
}

// Create a new IKEv2 configuration attribute
IKEV2_CP_ATTRIBUTE *IkeV2NewCpAttribute(UINT type, void *value, UINT size)
{
	IKEV2_CP_ATTRIBUTE *a = ZeroMalloc(sizeof(IKEV2_CP_ATTRIBUTE));
	a->Type = type;
	if (value != NULL && size > 0)
	{
		a->Value = MemToBuf(value, size);
	}
	return a;
}

//// AUTH payload (IKEv2)

// Parse the IKEv2 AUTH payload
bool IkeV2ParseAuthPayload(IKEV2_PACKET_AUTH_PAYLOAD *t, BUF *b)
{
	UCHAR ah[4];
	// Validate arguments
	if (t == NULL || b == NULL || b->Size < sizeof(ah))
	{
		return false;
	}

	// AuthMethod(1) Reserved(3) AuthenticationData(...)
	if (ReadBuf(b, ah, sizeof(ah)) != sizeof(ah))
	{
		return false;
	}

	t->Method = ah[0];
	t->AuthData = ReadRemainBuf(b);

	return true;
}

// Release the IKEv2 AUTH payload
void IkeV2FreeAuthPayload(IKEV2_PACKET_AUTH_PAYLOAD *t)
{
	if (t == NULL)
	{
		return;
	}

	if (t->AuthData != NULL)
	{
		FreeBuf(t->AuthData);
	}
}

// Build the IKEv2 AUTH payload
BUF *IkeV2BuildAuthPayload(IKEV2_PACKET_AUTH_PAYLOAD *t)
{
	BUF *b;
	UCHAR ah[4];
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(ah, sizeof(ah));
	ah[0] = t->Method;

	b = NewBuf();
	WriteBuf(b, ah, sizeof(ah));

	if (t->AuthData != NULL && t->AuthData->Size > 0)
	{
		WriteBufBuf(b, t->AuthData);
	}

	return b;
}

// Create a new IKEv2 AUTH payload
IKE_PACKET_PAYLOAD *IkeV2NewAuthPayload(UCHAR method, void *auth_data, UINT auth_size)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (auth_data == NULL || auth_size == 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKEV2_PAYLOAD_AUTH);
	p->Payload.AuthV2.Method = method;
	p->Payload.AuthV2.AuthData = MemToBuf(auth_data, auth_size);

	return p;
}

//// ID payload (IKEv2)

// Create a new IKEv2 IDi / IDr payload
IKE_PACKET_PAYLOAD *IkeV2NewIdPayload(UCHAR payload_type, UCHAR id_type, void *id_data, UINT id_size)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if ((payload_type != IKEV2_PAYLOAD_ID_INITIATOR && payload_type != IKEV2_PAYLOAD_ID_RESPONDER) ||
		id_data == NULL || id_size == 0)
	{
		return NULL;
	}

	p = IkeNewIdPayload(id_type, 0, 0, id_data, id_size);
	if (p != NULL)
	{
		p->PayloadType = payload_type;
	}

	return p;
}

//// Key derivation (RFC 7296 section 2.13)

// Calculate prf+ (K, S), generating any number of keying bytes
void IkeCalcPrfPlus(IKE_HASH *prf, void *key, UINT key_size, void *seed, UINT seed_size, void *dst, UINT dst_size)
{
	UCHAR t[IKE_MAX_HASH_SIZE];
	UCHAR *out;
	UINT generated = 0;
	UINT t_size = 0;
	UCHAR counter = 1;
	// Validate arguments
	if (prf == NULL || key == NULL || key_size == 0 || seed == NULL || seed_size == 0 ||
		dst == NULL || dst_size == 0)
	{
		return;
	}

	out = (UCHAR *)dst;

	// T(1) = prf(K, S | 0x01), T(n) = prf(K, T(n-1) | S | n)
	while (generated < dst_size)
	{
		BUF *b = NewBuf();
		UINT take;

		if (t_size >= 1)
		{
			WriteBuf(b, t, t_size);
		}
		WriteBuf(b, seed, seed_size);
		WriteBuf(b, &counter, 1);

		IkeHMac(prf, t, key, key_size, b->Buf, b->Size);

		FreeBuf(b);

		t_size = prf->HashSize;
		take = MIN(t_size, dst_size - generated);
		Copy(out + generated, t, take);
		generated += take;

		counter++;
	}
}

// Calculate prf+ (K, S) and return the result as a BUF
BUF *IkeCalcPrfPlusBuf(IKE_HASH *prf, void *key, UINT key_size, void *seed, UINT seed_size, UINT dst_size)
{
	UCHAR *tmp;
	BUF *b;
	// Validate arguments
	if (prf == NULL || dst_size == 0)
	{
		return NULL;
	}

	tmp = ZeroMalloc(dst_size);

	IkeCalcPrfPlus(prf, key, key_size, seed, seed_size, tmp, dst_size);

	b = MemToBuf(tmp, dst_size);

	Free(tmp);

	return b;
}
