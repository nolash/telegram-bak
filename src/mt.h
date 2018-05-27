#ifndef TGBK_MT_H_
#define TGBK_MT_H_

#define TGBK_FINGERPRINT_SIZE 8

#define TGBK_CMD_REQ_PQ "req_pq_multi nonce:int128 = ResPQ"
#define TGBK_CMD_RES_PQ ""
#define TGBK_CMD_REQ_DH_PARAMS "req_DH_params nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params"

#define TGBK_CMD_PQ_INNER_DATA "p_q_inner_data pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data"

int tgbk_pad(int l, char *v);
int tgbk_string_unserialize(const unsigned char *v, int *t, int *l, unsigned char **zR, unsigned char **zO);
int tgbk_string_serialize(int l, const char *v, unsigned char **zS);
int tgbk_type_wrap(const char *t, int l, const unsigned char *v, unsigned char **zT);
int tgbk_metadata_wrap(int l, const unsigned char *v, unsigned char **zM);
int tgbk_transport_wrap(int l, const unsigned char *v, unsigned char **zT);
int tgbk_transport_verify(int l, const unsigned char *v);

void tgbk_set_auth_key();
void tgbk_init();

#endif
