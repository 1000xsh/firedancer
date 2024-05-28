#include <openssl/sha.h>

#define CHAT_PAGE                                                       \
  "<html>\n"                                                                  \
  "<head>\n"                                                                  \
  "<title>WebSocket chat</title>\n"                                           \
  "<script>\n"                                                                \
  "document.addEventListener('DOMContentLoaded', function() {\n"              \
  "  const ws = new WebSocket('ws:/" "/' + window.location.host);\n"          \
  "  const btn = document.getElementById('send');\n"                          \
  "  const msg = document.getElementById('msg');\n"                           \
  "  const log = document.getElementById('log');\n"                           \
  "  ws.onopen = function() {\n"                                              \
  "    log.value += 'Connected\\n';\n"                                        \
  "  };\n"                                                                    \
  "  ws.onclose = function() {\n"                                             \
  "    log.value += 'Disconnected\\n';\n"                                     \
  "  };\n"                                                                    \
  "  ws.onmessage = function(ev) {\n"                                         \
  "    log.value += ev.data + '\\n';\n"                                       \
  "  };\n"                                                                    \
  "  btn.onclick = function() {\n"                                            \
  "    log.value += '<You>: ' + msg.value + '\\n';\n"                         \
  "    ws.send(msg.value);\n"                                                 \
  "  };\n"                                                                    \
  "  msg.onkeyup = function(ev) {\n"                                          \
  "    if (ev.keyCode === 13) {\n"                                            \
  "      ev.preventDefault();\n"                                              \
  "      ev.stopPropagation();\n"                                             \
  "      btn.click();\n"                                                      \
  "      msg.value = '';\n"                                                   \
  "    }\n"                                                                   \
  "  };\n"                                                                    \
  "});\n"                                                                     \
  "</script>\n"                                                               \
  "</head>\n"                                                                 \
  "<body>\n"                                                                  \
  "<input type='text' id='msg' autofocus/>\n"                                 \
  "<input type='button' id='send' value='Send' /><br /><br />\n"              \
  "<textarea id='log' rows='20' cols='28'></textarea>\n"                      \
  "</body>\n"                                                                 \
  "</html>"
#define BAD_REQUEST_PAGE                                                      \
  "<html>\n"                                                                  \
  "<head>\n"                                                                  \
  "<title>WebSocket chat</title>\n"                                           \
  "</head>\n"                                                                 \
  "<body>\n"                                                                  \
  "Bad Request\n"                                                             \
  "</body>\n"                                                                 \
  "</html>\n"
#define UPGRADE_REQUIRED_PAGE                                                 \
  "<html>\n"                                                                  \
  "<head>\n"                                                                  \
  "<title>WebSocket chat</title>\n"                                           \
  "</head>\n"                                                                 \
  "<body>\n"                                                                  \
  "Upgrade required\n"                                                        \
  "</body>\n"                                                                 \
  "</html>\n"

#define WS_SEC_WEBSOCKET_VERSION "13"
#define WS_UPGRADE_VALUE "websocket"
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_GUID_LEN 36
#define WS_KEY_LEN 24
#define WS_KEY_GUID_LEN ((WS_KEY_LEN) + (WS_GUID_LEN))
#define WS_FIN 128
#define WS_OPCODE_TEXT_FRAME 1
#define WS_OPCODE_CON_CLOSE_FRAME 8
#define SHA1HashSize 20

#define MAX_CLIENTS 10

static MHD_socket CLIENT_SOCKS[MAX_CLIENTS];

struct WsData
{
  struct MHD_UpgradeResponseHandle *urh;
  MHD_socket sock;
};



static enum MHD_Result
is_websocket_request (struct MHD_Connection *con, const char *upg_header,
                      const char *con_header)
{

  (void) con;  /* Unused. Silent compiler warning. */

  return ((upg_header != NULL) && (con_header != NULL)
          && (0 == strcmp (upg_header, WS_UPGRADE_VALUE))
          && (NULL != strstr (con_header, "Upgrade")))
         ? MHD_YES
         : MHD_NO;
}

static void do_nothing(void * arg) { (void)arg; }

static enum MHD_Result
send_chat_page (struct MHD_Connection *con)
{
  struct MHD_Response *res;
  enum MHD_Result ret;

  res = MHD_create_response_from_buffer_with_free_callback (strlen (CHAT_PAGE), (void *) CHAT_PAGE, do_nothing);
  ret = MHD_queue_response (con, MHD_HTTP_OK, res);
  MHD_destroy_response (res);
  return ret;
}


static enum MHD_Result
send_bad_request (struct MHD_Connection *con)
{
  struct MHD_Response *res;
  enum MHD_Result ret;

  res = MHD_create_response_from_buffer_with_free_callback (strlen (BAD_REQUEST_PAGE), (void *) BAD_REQUEST_PAGE, do_nothing);
  ret = MHD_queue_response (con, MHD_HTTP_BAD_REQUEST, res);
  MHD_destroy_response (res);
  return ret;
}


static enum MHD_Result
send_upgrade_required (struct MHD_Connection *con)
{
  struct MHD_Response *res;
  enum MHD_Result ret;

  res = MHD_create_response_from_buffer_with_free_callback (strlen (UPGRADE_REQUIRED_PAGE), (void *) UPGRADE_REQUIRED_PAGE, do_nothing);
  if (MHD_YES !=
      MHD_add_response_header (res, MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION,
                               WS_SEC_WEBSOCKET_VERSION))
  {
    MHD_destroy_response (res);
    return MHD_NO;
  }
  ret = MHD_queue_response (con, MHD_HTTP_UPGRADE_REQUIRED, res);
  MHD_destroy_response (res);
  return ret;
}


static enum MHD_Result
ws_get_accept_value (const char *key, char * val)
{
  SHA_CTX ctx;
  unsigned char hash[SHA1HashSize];

  if ( (NULL == key) || (WS_KEY_LEN != strlen (key)))
  {
    return MHD_NO;
  }
  char str[WS_KEY_LEN + WS_GUID_LEN + 1];
  strncpy (str, key, (WS_KEY_LEN + 1));
  strncpy (str + WS_KEY_LEN, WS_GUID, WS_GUID_LEN + 1);
  SHA1_Init (&ctx);
  SHA1_Update (&ctx, (const unsigned char *) str, WS_KEY_GUID_LEN);
  if (!SHA1_Final (hash, &ctx))
  {
    return MHD_NO;
  }
  ulong len = fd_base64_encode(val, hash, SHA1HashSize);
  val[len] = '\0';
  return MHD_YES;
}

static void
make_blocking (MHD_socket fd)
{
#if defined(MHD_POSIX_SOCKETS)
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    abort ();
  if ((flags & ~O_NONBLOCK) != flags)
    if (-1 == fcntl (fd, F_SETFL, flags & ~O_NONBLOCK))
      abort ();
#elif defined(MHD_WINSOCK_SOCKETS)
  unsigned long flags = 0;

  if (0 != ioctlsocket (fd, (int) FIONBIO, &flags))
    abort ();
#endif /* MHD_WINSOCK_SOCKETS */
}


static size_t
send_all (MHD_socket sock, const unsigned char *buf, size_t len)
{
  ssize_t ret;
  size_t off;

  for (off = 0; off < len; off += (size_t) ret)
  {
#if ! defined(_WIN32) || defined(__CYGWIN__)
    ret = send (sock, (const void *) &buf[off], len - off, 0);
#else  /* Native W32 */
    ret = send (sock, (const void *) &buf[off], (int) (len - off), 0);
#endif /* Native W32 */
    if (0 > ret)
    {
      if (EAGAIN == errno)
      {
        ret = 0;
        continue;
      }
      break;
    }
    if (0 == ret)
    {
      break;
    }
  }
  return off;
}


static ssize_t
ws_send_frame (MHD_socket sock, const char *msg, size_t length)
{
  unsigned char *response;
  unsigned char frame[10];
  unsigned char idx_first_rdata;
  size_t idx_response;
  size_t output;
  MHD_socket isock;
  size_t i;

  frame[0] = (WS_FIN | WS_OPCODE_TEXT_FRAME);
  if (length <= 125)
  {
    frame[1] = length & 0x7F;
    idx_first_rdata = 2;
  }
#if SIZEOF_SIZE_T > 4
  else if (0xFFFF < length)
  {
    frame[1] = 127;
    frame[2] = (unsigned char) ((length >> 56) & 0xFF);
    frame[3] = (unsigned char) ((length >> 48) & 0xFF);
    frame[4] = (unsigned char) ((length >> 40) & 0xFF);
    frame[5] = (unsigned char) ((length >> 32) & 0xFF);
    frame[6] = (unsigned char) ((length >> 24) & 0xFF);
    frame[7] = (unsigned char) ((length >> 16) & 0xFF);
    frame[8] = (unsigned char) ((length >> 8) & 0xFF);
    frame[9] = (unsigned char) (length & 0xFF);
    idx_first_rdata = 10;
  }
#endif /* SIZEOF_SIZE_T > 4 */
  else
  {
    frame[1] = 126;
    frame[2] = (length >> 8) & 0xFF;
    frame[3] = length & 0xFF;
    idx_first_rdata = 4;
  }
  idx_response = 0;
  response = malloc (idx_first_rdata + length + 1);
  if (NULL == response)
  {
    return -1;
  }
  for (i = 0; i < idx_first_rdata; i++)
  {
    response[i] = frame[i];
    idx_response++;
  }
  for (i = 0; i < length; i++)
  {
    response[idx_response] = (unsigned char) msg[i];
    idx_response++;
  }
  response[idx_response] = '\0';
  output = 0;
  for (i = 0; i < MAX_CLIENTS; i++)
  {
    isock = CLIENT_SOCKS[i];
    if ((isock != MHD_INVALID_SOCKET) && (isock != sock))
    {
      output += send_all (isock, response, idx_response);
    }
  }
  free (response);
  return (ssize_t) output;
}


static unsigned char *
ws_receive_frame (unsigned char *frame, ssize_t *length, int *type)
{
  unsigned char masks[4];
  unsigned char mask;
  unsigned char *msg;
  unsigned char flength;
  unsigned char idx_first_mask;
  unsigned char idx_first_data;
  size_t data_length;
  int i;
  int j;

  msg = NULL;
  if (frame[0] == (WS_FIN | WS_OPCODE_TEXT_FRAME))
  {
    *type = WS_OPCODE_TEXT_FRAME;
    idx_first_mask = 2;
    mask = frame[1];
    flength = mask & 0x7F;
    if (flength == 126)
    {
      idx_first_mask = 4;
    }
    else if (flength == 127)
    {
      idx_first_mask = 10;
    }
    idx_first_data = (unsigned char) (idx_first_mask + 4);
    data_length = (size_t) *length - idx_first_data;
    masks[0] = frame[idx_first_mask + 0];
    masks[1] = frame[idx_first_mask + 1];
    masks[2] = frame[idx_first_mask + 2];
    masks[3] = frame[idx_first_mask + 3];
    msg = malloc (data_length + 1);
    if (NULL != msg)
    {
      for (i = idx_first_data, j = 0; i < *length; i++, j++)
      {
        msg[j] = frame[i] ^ masks[j % 4];
      }
      *length = (ssize_t) data_length;
      msg[j] = '\0';
    }
  }
  else if (frame[0] == (WS_FIN | WS_OPCODE_CON_CLOSE_FRAME))
  {
    *type = WS_OPCODE_CON_CLOSE_FRAME;
  }
  else
  {
    *type = frame[0] & 0x0F;
  }
  return msg;
}


static void *
run_usock (void *cls)
{
  struct WsData *ws = cls;
  struct MHD_UpgradeResponseHandle *urh = ws->urh;
  unsigned char buf[2048];
  unsigned char *msg;
  char *text;
  ssize_t got;
  int type;
  int i;

  make_blocking (ws->sock);
  while (1)
  {
    got = recv (ws->sock, (void *) buf, sizeof (buf), 0);
    if (0 >= got)
    {
      break;
    }
    msg = ws_receive_frame (buf, &got, &type);
    if (NULL == msg)
    {
      break;
    }
    if (type == WS_OPCODE_TEXT_FRAME)
    {
      ssize_t sent;
      int buf_size;
      buf_size = snprintf (NULL, 0, "User#%d: %s", (int) ws->sock, msg);
      if (0 < buf_size)
      {
        text = malloc ((size_t) buf_size + 1);
        if (NULL != text)
        {
          if (snprintf (text, (size_t) buf_size + 1,
                        "User#%d: %s", (int) ws->sock, msg) == buf_size)
            sent = ws_send_frame (ws->sock, text, (size_t) buf_size);
          else
            sent = -1;
          free (text);
        }
        else
          sent = -1;
      }
      else
        sent = -1;
      free (msg);
      if (-1 == sent)
      {
        break;
      }
    }
    else
    {
      if (type == WS_OPCODE_CON_CLOSE_FRAME)
      {
        free (msg);
        break;
      }
    }
  }
  for (i = 0; i < MAX_CLIENTS; i++)
  {
    if (CLIENT_SOCKS[i] == ws->sock)
    {
      CLIENT_SOCKS[i] = MHD_INVALID_SOCKET;
      break;
    }
  }
  free (ws);
  MHD_upgrade_action (urh, MHD_UPGRADE_ACTION_CLOSE);
  return NULL;
}


static void
uh_cb (void *cls, struct MHD_Connection *con, void *req_cls,
       const char *extra_in, size_t extra_in_size, MHD_socket sock,
       struct MHD_UpgradeResponseHandle *urh)
{
  struct WsData *ws;
  pthread_t pt;
  int sock_overflow;
  int i;

  (void) cls;            /* Unused. Silent compiler warning. */
  (void) con;            /* Unused. Silent compiler warning. */
  (void) req_cls;        /* Unused. Silent compiler warning. */
  (void) extra_in;       /* Unused. Silent compiler warning. */
  (void) extra_in_size;  /* Unused. Silent compiler warning. */

  ws = malloc (sizeof (struct WsData));
  if (NULL == ws)
    abort ();
  memset (ws, 0, sizeof (struct WsData));
  ws->sock = sock;
  ws->urh = urh;
  sock_overflow = MHD_YES;
  for (i = 0; i < MAX_CLIENTS; i++)
  {
    if (MHD_INVALID_SOCKET == CLIENT_SOCKS[i])
    {
      CLIENT_SOCKS[i] = ws->sock;
      sock_overflow = MHD_NO;
      break;
    }
  }
  if (sock_overflow)
  {
    free (ws);
    MHD_upgrade_action (urh, MHD_UPGRADE_ACTION_CLOSE);
    return;
  }
  if (0 != pthread_create (&pt, NULL, &run_usock, ws))
    abort ();
  /* Note that by detaching like this we make it impossible to ensure
     a clean shutdown, as the we stop the daemon even if a worker thread
     is still running. Alas, this is a simple example... */
  pthread_detach (pt);
}


static enum MHD_Result
ws_handler (void *cls, struct MHD_Connection *con, const char *url,
            const char *method, const char *version, const char *upload_data,
            size_t *upload_data_size, void **req_cls)
{
  struct MHD_Response *res;
  const char *upg_header;
  const char *con_header;
  const char *ws_version_header;
  const char *ws_key_header;
  enum MHD_Result ret;
  size_t key_size;

  (void) cls;               /* Unused. Silent compiler warning. */
  (void) url;               /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (NULL == *req_cls)
  {
    *req_cls = (void *) 1;
    return MHD_YES;
  }
  *req_cls = NULL;
  upg_header = MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                            MHD_HTTP_HEADER_UPGRADE);
  con_header = MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                            MHD_HTTP_HEADER_CONNECTION);
  if (MHD_NO == is_websocket_request (con, upg_header, con_header))
  {
    return send_chat_page (con);
  }
  if ((0 != strcmp (method, MHD_HTTP_METHOD_GET))
      || (0 != strcmp (version, MHD_HTTP_VERSION_1_1)))
  {
    return send_bad_request (con);
  }
  ws_version_header =
    MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                 MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION);
  if ((NULL == ws_version_header)
      || (0 != strcmp (ws_version_header, WS_SEC_WEBSOCKET_VERSION)))
  {
    return send_upgrade_required (con);
  }
  ret = MHD_lookup_connection_value_n (con, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY,
                                       strlen (
                                         MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY),
                                       &ws_key_header, &key_size);
  if ((MHD_NO == ret) || (key_size != WS_KEY_LEN))
  {
    return send_bad_request (con);
  }
  char ws_ac_value[2*SHA1HashSize+1];
  ret = ws_get_accept_value (ws_key_header, ws_ac_value);
  if (MHD_NO == ret)
  {
    return ret;
  }
  res = MHD_create_response_for_upgrade (&uh_cb, NULL);
  if (MHD_YES !=
      MHD_add_response_header (res, MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT,
                               ws_ac_value))
  {
    MHD_destroy_response (res);
    return MHD_NO;
  }
  if (MHD_YES !=
      MHD_add_response_header (res, MHD_HTTP_HEADER_UPGRADE, WS_UPGRADE_VALUE))
  {
    MHD_destroy_response (res);
    return MHD_NO;
  }
  ret = MHD_queue_response (con, MHD_HTTP_SWITCHING_PROTOCOLS, res);
  MHD_destroy_response (res);
  return ret;
}
