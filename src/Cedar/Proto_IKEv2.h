// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IKEv2.h
// Header of Proto_IKEv2.c

#ifndef	PROTO_IKEV2_H
#define	PROTO_IKEV2_H

#include "Proto_IKE.h"

//// Constants

// IKEv2 notify message type used by this module (complement of Proto_IkePacket.h)
#define	IKEV2_NOTIFY_NO_ADDITIONAL_SAS					35

//// Function prototype

// Entry point called from ProcIKEPacketRecv for every IKEv2 (major version 2) packet
void ProcIkeV2PacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);

// Exchange processing (responder side)
void IkeV2ProcSaInit(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c);
void IkeV2ProcIkeAuth(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa);
void IkeV2ProcInformational(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa);
void IkeV2ProcCreateChildSa(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header, IKE_CLIENT *c, IKE_SA *sa);

// Sending helpers
bool IkeV2RecvEncrypted(IKE_SERVER *ike, IKE_SA *sa, UDPPACKET *p, IKE_PACKET *header);
void IkeV2SendEncryptedResponse(IKE_SERVER *ike, IKE_SA *sa, UCHAR exchange_type, UINT message_id, LIST *payload_list);
void IkeV2SendEncryptedNotify(IKE_SERVER *ike, IKE_SA *sa, UCHAR exchange_type, UINT message_id,
							  USHORT notify_type, void *notify_data, UINT notify_data_size);
void IkeV2SendPlainNotifyResponse(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET *header,
								   USHORT notify_type, void *notify_data, UINT notify_data_size);
void IkeV2MarkIkeSaDeleted(IKE_SERVER *ike, IKE_SA *sa);
void IkeV2MarkIkeClientDeleted(IKE_SERVER *ike, IKE_CLIENT *c);

// Key derivation
bool IkeV2CalcKeymat(IKE_SERVER *ike, IKE_SA *sa, void *g_ir, UINT g_ir_size);
BUF *IkeV2CalcChildSaKeymat(IKE_SERVER *ike, IKE_SA *sa, UINT keymat_size);

// Authentication (RFC 7296 section 2.15)
BUF *IkeV2CalcSignedOctets(IKE_SA *sa, BUF *real_message, BUF *nonce, void *skp, UINT skp_size, BUF *id_body);
bool IkeV2VerifyInitiatorAuthSecret(IKE_SERVER *ike, IKE_SA *sa, IKE_PACKET_PAYLOAD *auth_payload,
									void *secret, UINT secret_size);
IKE_PACKET_PAYLOAD *IkeV2BuildAuthSecret(IKE_SERVER *ike, IKE_SA *sa, void *secret, UINT secret_size,
										 BUF *real_message, BUF *nonce, void *skp, UINT skp_size, BUF *id_body);

// Proposal selection
bool IkeV2SelectIkeSaProposal(IKE_SERVER *ike, IKE_PACKET_PAYLOAD *sa_payload,
							  IKE_SA_TRANSFORM_SETTING *setting, USHORT *invalid_ke_group);
bool IkeV2SelectChildSaProposal(IKE_SERVER *ike, IKE_PACKET_PAYLOAD *sa_payload,
								IPSEC_SA_TRANSFORM_SETTING *setting, UINT *client_spi);
IKE_PACKET_PAYLOAD *IkeV2BuildIkeSaResponseProposal(IKE_SERVER *ike, IKE_SA_TRANSFORM_SETTING *setting);
IKE_PACKET_PAYLOAD *IkeV2BuildChildSaResponseProposal(IKE_SERVER *ike, IPSEC_SA_TRANSFORM_SETTING *setting, UINT our_spi);

// ESP anti-replay window (RFC 4303 section 3.4.3)
bool IkeV2EspReplayCheck(IPSECSA *sa, UINT seq);
void IkeV2EspReplayUpdate(IPSECSA *sa, UINT seq);

// Certificate signature AUTH (RFC 7427 digital signature method)
IKE_PACKET_PAYLOAD *IkeV2BuildSignatureAuth(IKE_SERVER *ike, IKE_SA *sa, BUF *real_message, BUF *nonce,
											void *skp, UINT skp_size, BUF *id_body, bool prefer_sha256);

// Utility
IKE_PACKET_PAYLOAD *IkeV2GetNotifyPayload(IKE_PACKET *pr, UINT notify_type, UINT index);
void IkeV2CheckNatD(IKE_SERVER *ike, IKE_PACKET *pr, UDPPACKET *p, IKE_PACKET *header, IKE_SA *sa);
IKE_HASH *IkeV2GetSha1(IKE_SERVER *ike);

#endif	// PROTO_IKEV2_H
