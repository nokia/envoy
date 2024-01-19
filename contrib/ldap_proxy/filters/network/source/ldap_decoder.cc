#include "contrib/ldap_proxy/filters/network/source/ldap_decoder.h"

#include <cstring>
#include <vector>
#include "lber.h"
#include "ldap.h"

#include "absl/strings/str_split.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace LdapProxy {

int sbBuffSetup(Sockbuf_IO_Desc* sbiod, void* arg) {
  // sbiod->sbiod_pvt = LBER_MALLOC( strlen( arg ) + 1 );
  // if ( sbiod->sbiod_pvt == NULL ) return -1;

  // strcpy( (char *)sbiod->sbiod_pvt, (char *)arg );
  sbiod->sbiod_pvt = arg;
  return 0;
}

int sbBuffRemove(Sockbuf_IO_Desc* sbiod) {
  // LBER_FREE( sbiod->sbiod_pvt );
  sbiod->sbiod_pvt = nullptr;
  return 0;
}

ber_slen_t sbBuffRead(Sockbuf_IO_Desc* sbiod, void* buf, ber_len_t len) {
  void* p = sbiod->sbiod_pvt;
  Buffer::Instance& data = *(reinterpret_cast<Buffer::Instance*>(p));
  if (len <= data.length()) {
    memcpy(buf, data.linearize(data.length()), data.length());
    data.drain(len);
    return len;
  } else {
    auto length = data.length();
    memcpy(buf, data.linearize(data.length()), data.length());
    data.drain(length);
    return length;
  }
}

ber_slen_t sbBuffWrite(Sockbuf_IO_Desc* sbiod, void* buf, ber_len_t len) {
  void* p = sbiod->sbiod_pvt;
  Buffer::Instance& data = *(reinterpret_cast<Buffer::Instance*>(p));
  //data = Buffer::OwnedImpl(buf, len);
  data.add(buf, len);

  std::cout << "XXXXX Write0 " << buf << std::endl;
  std::cout << "XXXXX Write1 " << len << std::endl;
  std::cout << "XXXXX Write2 " << data.length() << std::endl;
  return len;
}

bool DecoderImpl::isStartTLS(Buffer::Instance& data) {
  bool isStartTLS = false;

  Sockbuf_IO ber_sockbuf_io_buff = {
      sbBuffSetup,  /* sbi_setup */
      sbBuffRemove, /* sbi_remove */
      nullptr,      /* sbi_ctrl */
      sbBuffRead,   /* sbi_read */
      sbBuffWrite,  /* sbi_write */
      nullptr       /* sbi_close */
  };

  Sockbuf* sb = ber_sockbuf_alloc();
  ber_sockbuf_add_io(sb, &ber_sockbuf_io_buff, LBER_SBIOD_LEVEL_PROVIDER, &data);

  BerElement* ber = ber_alloc_t(LBER_USE_DER);
  if (ber == nullptr) {
    return isStartTLS;
  }

  ber_tag_t tag;
  ber_len_t len;

  for (;;) {
    tag = ber_get_next(sb, &len, ber);
    if (tag != LBER_ERROR) {
      break;
    }

    return isStartTLS;
  }

  if (tag != LDAP_TAG_MESSAGE) {
    return isStartTLS;
    // TODO ERROR
  }

  ber_int_t msg_id;
  tag = ber_scanf(ber, "i", &msg_id);
  if (tag != LDAP_TAG_MSGID) {
    // TODO ERROR
    return isStartTLS;
  }

  tag = ber_scanf(ber, "{");
  if (tag != LDAP_REQ_EXTENDED) {
    // TODO ERROR
    return isStartTLS;
  }

  char buf[128] = {0};
  tag = ber_scanf(ber, "{s}", buf, sizeof(buf));
  if ((tag != LDAP_TAG_EXOP_REQ_OID) || (!strncmp(buf, LDAP_EXOP_START_TLS, 22))) {
    // TODO ERROR
    return isStartTLS;
  }

  ber_sockbuf_free(sb);
  ber_free(ber, 1);

  isStartTLS = true;
  return isStartTLS;
}

#define BODY_FORMAT(...)                                                                           \
  []() -> std::unique_ptr<Message> { return createMsgBodyReader<__VA_ARGS__>(); }
#define NO_BODY BODY_FORMAT()

constexpr absl::string_view FRONTEND = "Frontend";
constexpr absl::string_view BACKEND = "Backend";

void DecoderImpl::initialize() {
  // Special handler for first message of the transaction.
  first_ =
      MessageProcessor{"Startup", BODY_FORMAT(Int32, Repeated<String>), {&DecoderImpl::onStartup}};

  // Frontend messages.
  FE_messages_.direction_ = FRONTEND;

  // Setup handlers for known messages.
  absl::flat_hash_map<char, MessageProcessor>& FE_known_msgs = FE_messages_.messages_;

  // Handler for known Frontend messages.
  FE_known_msgs['B'] = MessageProcessor{
      "Bind", BODY_FORMAT(String, String, Array<Int16>, Array<VarByteN>, Array<Int16>), {}};
  FE_known_msgs['C'] = MessageProcessor{"Close", BODY_FORMAT(Byte1, String), {}};
  FE_known_msgs['d'] = MessageProcessor{"CopyData", BODY_FORMAT(ByteN), {}};
  FE_known_msgs['c'] = MessageProcessor{"CopyDone", NO_BODY, {}};
  FE_known_msgs['f'] = MessageProcessor{"CopyFail", BODY_FORMAT(String), {}};
  FE_known_msgs['D'] = MessageProcessor{"Describe", BODY_FORMAT(Byte1, String), {}};
  FE_known_msgs['E'] = MessageProcessor{"Execute", BODY_FORMAT(String, Int32), {}};
  FE_known_msgs['H'] = MessageProcessor{"Flush", NO_BODY, {}};
  FE_known_msgs['F'] = MessageProcessor{
      "FunctionCall", BODY_FORMAT(Int32, Array<Int16>, Array<VarByteN>, Int16), {}};
  FE_known_msgs['p'] =
      MessageProcessor{"PasswordMessage/GSSResponse/SASLInitialResponse/SASLResponse",
                       BODY_FORMAT(Int32, ByteN),
                       {}};
  FE_known_msgs['P'] =
      MessageProcessor{"Parse", BODY_FORMAT(String, String, Array<Int32>), {&DecoderImpl::onParse}};
  FE_known_msgs['Q'] = MessageProcessor{"Query", BODY_FORMAT(String), {&DecoderImpl::onQuery}};
  FE_known_msgs['S'] = MessageProcessor{"Sync", NO_BODY, {}};
  FE_known_msgs['X'] =
      MessageProcessor{"Terminate", NO_BODY, {&DecoderImpl::decodeFrontendTerminate}};

  // Handler for unknown Frontend messages.
  FE_messages_.unknown_ =
      MessageProcessor{"Other", BODY_FORMAT(ByteN), {&DecoderImpl::incMessagesUnknown}};

  // Backend messages.
  BE_messages_.direction_ = BACKEND;

  // Setup handlers for known messages.
  absl::flat_hash_map<char, MessageProcessor>& BE_known_msgs = BE_messages_.messages_;

  // Handler for known Backend messages.
  BE_known_msgs['R'] =
      MessageProcessor{"Authentication", BODY_FORMAT(ByteN), {&DecoderImpl::decodeAuthentication}};
  BE_known_msgs['K'] = MessageProcessor{"BackendKeyData", BODY_FORMAT(Int32, Int32), {}};
  BE_known_msgs['2'] = MessageProcessor{"BindComplete", NO_BODY, {}};
  BE_known_msgs['3'] = MessageProcessor{"CloseComplete", NO_BODY, {}};
  BE_known_msgs['C'] = MessageProcessor{
      "CommandComplete", BODY_FORMAT(String), {&DecoderImpl::decodeBackendStatements}};
  BE_known_msgs['d'] = MessageProcessor{"CopyData", BODY_FORMAT(ByteN), {}};
  BE_known_msgs['c'] = MessageProcessor{"CopyDone", NO_BODY, {}};
  BE_known_msgs['G'] = MessageProcessor{"CopyInResponse", BODY_FORMAT(Int8, Array<Int16>), {}};
  BE_known_msgs['H'] = MessageProcessor{"CopyOutResponse", BODY_FORMAT(Int8, Array<Int16>), {}};
  BE_known_msgs['W'] = MessageProcessor{"CopyBothResponse", BODY_FORMAT(Int8, Array<Int16>), {}};
  BE_known_msgs['D'] = MessageProcessor{"DataRow", BODY_FORMAT(Array<VarByteN>), {}};
  BE_known_msgs['I'] = MessageProcessor{"EmptyQueryResponse", NO_BODY, {}};
  BE_known_msgs['E'] = MessageProcessor{
      "ErrorResponse", BODY_FORMAT(Byte1, String), {&DecoderImpl::decodeBackendErrorResponse}};
  BE_known_msgs['V'] = MessageProcessor{"FunctionCallResponse", BODY_FORMAT(VarByteN), {}};
  BE_known_msgs['v'] = MessageProcessor{"NegotiateProtocolVersion", BODY_FORMAT(ByteN), {}};
  BE_known_msgs['n'] = MessageProcessor{"NoData", NO_BODY, {}};
  BE_known_msgs['N'] = MessageProcessor{
      "NoticeResponse", BODY_FORMAT(ByteN), {&DecoderImpl::decodeBackendNoticeResponse}};
  BE_known_msgs['A'] =
      MessageProcessor{"NotificationResponse", BODY_FORMAT(Int32, String, String), {}};
  BE_known_msgs['t'] = MessageProcessor{"ParameterDescription", BODY_FORMAT(Array<Int32>), {}};
  BE_known_msgs['S'] = MessageProcessor{"ParameterStatus", BODY_FORMAT(String, String), {}};
  BE_known_msgs['1'] = MessageProcessor{"ParseComplete", NO_BODY, {}};
  BE_known_msgs['s'] = MessageProcessor{"PortalSuspend", NO_BODY, {}};
  BE_known_msgs['Z'] = MessageProcessor{"ReadyForQuery", BODY_FORMAT(Byte1), {}};
  BE_known_msgs['T'] = MessageProcessor{
      "RowDescription",
      BODY_FORMAT(Array<Sequence<String, Int32, Int16, Int32, Int16, Int32, Int16>>),
      {}};

  // Handler for unknown Backend messages.
  BE_messages_.unknown_ =
      MessageProcessor{"Other", BODY_FORMAT(ByteN), {&DecoderImpl::incMessagesUnknown}};

  // Setup hash map for handling backend statements.
  BE_statements_["BEGIN"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Other);
    callbacks_->incTransactions();
    session_.setInTransaction(true);
  };
  BE_statements_["ROLLBACK"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Other);
    callbacks_->incTransactionsRollback();
    session_.setInTransaction(false);
  };
  BE_statements_["START"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Other);
    callbacks_->incTransactions();
    session_.setInTransaction(true);
  };
  BE_statements_["COMMIT"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Other);
    session_.setInTransaction(false);
    callbacks_->incTransactionsCommit();
  };
  BE_statements_["SELECT"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Select);
    callbacks_->incTransactions();
    callbacks_->incTransactionsCommit();
  };
  BE_statements_["INSERT"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Insert);
    callbacks_->incTransactions();
    callbacks_->incTransactionsCommit();
  };
  BE_statements_["UPDATE"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Update);
    callbacks_->incTransactions();
    callbacks_->incTransactionsCommit();
  };
  BE_statements_["DELETE"] = [this](DecoderImpl*) -> void {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Delete);
    callbacks_->incTransactions();
    callbacks_->incTransactionsCommit();
  };

  // Setup hash map for handling backend ErrorResponse messages.
  BE_errors_.keywords_["ERROR"] = [this](DecoderImpl*) -> void {
    callbacks_->incErrors(DecoderCallbacks::ErrorType::Error);
  };
  BE_errors_.keywords_["FATAL"] = [this](DecoderImpl*) -> void {
    callbacks_->incErrors(DecoderCallbacks::ErrorType::Fatal);
  };
  BE_errors_.keywords_["PANIC"] = [this](DecoderImpl*) -> void {
    callbacks_->incErrors(DecoderCallbacks::ErrorType::Panic);
  };
  // Setup handler which is called when decoder cannot decode the message and treats it as Unknown
  // Error message.
  BE_errors_.unknown_ = [this](DecoderImpl*) -> void {
    callbacks_->incErrors(DecoderCallbacks::ErrorType::Unknown);
  };

  // Setup hash map for handling backend NoticeResponse messages.
  BE_notices_.keywords_["WARNING"] = [this](DecoderImpl*) -> void {
    callbacks_->incNotices(DecoderCallbacks::NoticeType::Warning);
  };
  BE_notices_.keywords_["NOTICE"] = [this](DecoderImpl*) -> void {
    callbacks_->incNotices(DecoderCallbacks::NoticeType::Notice);
  };
  BE_notices_.keywords_["DEBUG"] = [this](DecoderImpl*) -> void {
    callbacks_->incNotices(DecoderCallbacks::NoticeType::Debug);
  };
  BE_notices_.keywords_["INFO"] = [this](DecoderImpl*) -> void {
    callbacks_->incNotices(DecoderCallbacks::NoticeType::Info);
  };
  BE_notices_.keywords_["LOG"] = [this](DecoderImpl*) -> void {
    callbacks_->incNotices(DecoderCallbacks::NoticeType::Log);
  };
  // Setup handler which is called when decoder cannot decode the message and treats it as Unknown
  // Notice message.
  BE_notices_.unknown_ = [this](DecoderImpl*) -> void {
    callbacks_->incNotices(DecoderCallbacks::NoticeType::Unknown);
  };
}

/* Main handler for incoming messages. Messages are dispatched based on the
   current decoder's state.
*/
Decoder::Result DecoderImpl::onData(Buffer::Instance& data, bool frontend) {
  switch (state_) {
  case State::InitState:
    return onDataInit(data, frontend);
  case State::OutOfSyncState:
  case State::EncryptedState:
    return onDataIgnore(data, frontend);
  case State::InSyncState:
    return onDataInSync(data, frontend);
  case State::NegotiatingUpstreamSSL:
    return onDataInNegotiating(data, frontend);
  default:
    PANIC("not implemented");
  }
}

/* Handler for messages when decoder is in Init State. There are very few message types which
   are allowed in this state.
   If the initial message has the correct syntax and  indicates that session should be in
   clear-text, the decoder will move to InSyncState. If the initial message has the correct syntax
   and indicates that session should be encrypted, the decoder stays in InitState, because the
   initial message will be received again after transport socket negotiates SSL. If the message
   syntax is incorrect, the decoder will move to OutOfSyncState, in which messages are not parsed.
*/
Decoder::Result DecoderImpl::onDataInit(Buffer::Instance& data, bool) {
  ENVOY_LOG(trace, "onDataInit");
  ASSERT(state_ == State::InitState);

  // In Init state the minimum size of the message sufficient for parsing is 4 bytes.
  if (data.length() < 4) {
    // not enough data in the buffer.
    return Decoder::Result::NeedMoreData;
  }

  // FELIX do startTLS for LDAP for first message
  // TODO TCP reassemble
  Decoder::Result result = Decoder::Result::ReadyForNext;
  if (callbacks_->shouldEncryptUpstream()) {
    // Copy the received initial request.
    ENVOY_LOG(trace, "encryptUpstream");
    temp_storage_.add(data.linearize(data.length()), data.length());

    Sockbuf_IO ber_sockbuf_io_buff = {
	    sbBuffSetup,  /* sbi_setup */
	    sbBuffRemove, /* sbi_remove */
	    nullptr,      /* sbi_ctrl */
	    sbBuffRead,   /* sbi_read */
	    sbBuffWrite,  /* sbi_write */
	    nullptr       /* sbi_close */
    };

    Buffer::OwnedImpl ssl_request;
    Sockbuf* sb = ber_sockbuf_alloc();
    ber_sockbuf_add_io(sb, &ber_sockbuf_io_buff, LBER_SBIOD_LEVEL_PROVIDER, &ssl_request);

    // Send SSL request to upstream.
    BerElement* output = ber_alloc_t(LBER_USE_DER);
    ber_printf(output, "t{tit{ts}}", LDAP_TAG_MESSAGE, LDAP_TAG_MSGID, 1, LDAP_REQ_EXTENDED,
               LDAP_TAG_EXOP_REQ_OID, LDAP_EXOP_START_TLS);
    // ber is freed with freeit.
    ber_flush(sb, output, 1);

    ENVOY_LOG(trace, "sendUpstream {}", ssl_request.length());
    callbacks_->sendUpstream(ssl_request);
    result = Decoder::Result::Stopped;
    state_ = State::NegotiatingUpstreamSSL;
    //ber_free(output, 1);
    data.drain(data.length());
    ENVOY_LOG(trace, "Init Done");
  } else {
    state_ = State::InSyncState;
  }

#if 0
  // Validate the message before processing.
  const MsgBodyReader& f = std::get<1>(first_);
  const auto msgParser = f();
  // Run the validation.
  message_len_ = data.peekBEInt<uint32_t>(0);
  if (message_len_ > MAX_STARTUP_PACKET_LENGTH) {
    // Message does not conform to the expected format. Move to out-of-sync state.
    data.drain(data.length());
    state_ = State::OutOfSyncState;
    return Decoder::Result::ReadyForNext;
  }

  Message::ValidationResult validationResult = msgParser->validate(data, 4, message_len_ - 4);

  if (validationResult == Message::ValidationNeedMoreData) {
    return Decoder::Result::NeedMoreData;
  }

  if (validationResult == Message::ValidationFailed) {
    // Message does not conform to the expected format. Move to out-of-sync state.
    data.drain(data.length());
    state_ = State::OutOfSyncState;
    return Decoder::Result::ReadyForNext;
  }

  uint32_t code = data.peekBEInt<uint32_t>(4);
  // Startup message with 1234 in the most significant 16 bits
  // indicate request to encrypt.
  if (code >= 0x04d20000) {
    encrypted_ = true;
    // Handler for SSLRequest (Int32(80877103) = 0x04d2162f)
    // See details in https://www.ldapql.org/docs/current/protocol-message-formats.html.
    if (code == 0x04d2162f) {
      // Notify the filter that `SSLRequest` message was decoded.
      // If the filter returns true, it means to pass the message upstream
      // to the server. If it returns false it means, that filter will try
      // to terminate SSL session and SSLRequest should not be passed to the
      // server.
      encrypted_ = callbacks_->onSSLRequest();
    }

    // Count it as recognized frontend message.
    callbacks_->incMessagesFrontend();
    if (encrypted_) {
      ENVOY_LOG(trace, "ldap_proxy: detected encrypted traffic.");
      incSessionsEncrypted();
      state_ = State::EncryptedState;
    } else {
      result = Decoder::Result::Stopped;
      // Stay in InitState. After switch to SSL, another init packet will be sent.
    }
  } else {
    ENVOY_LOG(debug, "Detected version {}.{} of Ldap", code >> 16, code & 0x0000FFFF);
    if (callbacks_->shouldEncryptUpstream()) {
      // Copy the received initial request.
      temp_storage_.add(data.linearize(data.length()), data.length());
      // Send SSL request to upstream.
      Buffer::OwnedImpl ssl_request;
      uint32_t len = 8;
      ssl_request.writeBEInt<uint32_t>(len);
      uint32_t ssl_code = 0x04d2162f;
      ssl_request.writeBEInt<uint32_t>(ssl_code);

      callbacks_->sendUpstream(ssl_request);
      result = Decoder::Result::Stopped;
      state_ = State::NegotiatingUpstreamSSL;
    } else {
      state_ = State::InSyncState;
    }
  }
  data.drain(4);

  processMessageBody(data, FRONTEND, message_len_ - 4, first_, msgParser);
  data.drain(message_len_);
#endif
  return result;
}

/*
  Method invokes actions associated with message type and generate debug logs.
*/
void DecoderImpl::processMessageBody(Buffer::Instance& data, absl::string_view direction,
                                     uint32_t length, MessageProcessor& msg,
                                     const std::unique_ptr<Message>& parser) {
  uint32_t bytes_to_read = length;

  std::vector<MsgAction>& actions = std::get<2>(msg);
  if (!actions.empty()) {
    // Linearize the message for processing.
    message_.assign(std::string(static_cast<char*>(data.linearize(bytes_to_read)), bytes_to_read));

    // Invoke actions associated with the type of received message.
    for (const auto& action : actions) {
      action(this);
    }

    // Drop the linearized message.
    message_.erase();
  }

  ENVOY_LOG(debug, "({}) command = {} ({})", direction, command_, std::get<0>(msg));
  ENVOY_LOG(debug, "({}) length = {}", direction, message_len_);
  ENVOY_LOG(debug, "({}) message = {}", direction, genDebugMessage(parser, data, bytes_to_read));

  ENVOY_LOG(trace, "ldap_proxy: {} bytes remaining in buffer", data.length());

  data.drain(length);
}

/*
  onDataInSync is called when decoder is on-track with decoding messages.
  All previous messages has been decoded properly and decoder is able to find
  message boundaries.
*/
Decoder::Result DecoderImpl::onDataInSync(Buffer::Instance& data, bool frontend) {
  ENVOY_LOG(trace, "ldap_proxy: decoding {} bytes", data.length());

  ENVOY_LOG(trace, "ldap_proxy: parsing message, len {}", data.length());

  // The minimum size of the message sufficient for parsing is 5 bytes.
  if (data.length() < 5) {
    // not enough data in the buffer.
    return Decoder::Result::NeedMoreData;
  }

  data.copyOut(0, 1, &command_);
  ENVOY_LOG(trace, "ldap_proxy: command is {}", command_);

  // The 1 byte message type and message length should be in the buffer
  // Find the message processor and validate the message syntax.

  MsgGroup& msg_processor = std::ref(frontend ? FE_messages_ : BE_messages_);
  frontend ? callbacks_->incMessagesFrontend() : callbacks_->incMessagesBackend();

  // Set processing to the handler of unknown messages.
  // If message is found, the processing will be updated.
  std::reference_wrapper<MessageProcessor> msg = msg_processor.unknown_;

  auto it = msg_processor.messages_.find(command_);
  if (it != msg_processor.messages_.end()) {
    msg = std::ref((*it).second);
  }

  // Validate the message before processing.
  const MsgBodyReader& f = std::get<1>(msg.get());
  message_len_ = data.peekBEInt<uint32_t>(1);
  const auto msgParser = f();
  // Run the validation.
  // Because the message validation may return NeedMoreData error, data must stay intact (no
  // draining) until the remaining data arrives and validator will run again. Validator therefore
  // starts at offset 5 (1 byte message type and 4 bytes of length). This is in contrast to
  // processing of the message, which assumes that message has been validated and starts at the
  // beginning of the message.
  Message::ValidationResult validationResult = msgParser->validate(data, 5, message_len_ - 4);

  if (validationResult == Message::ValidationNeedMoreData) {
    ENVOY_LOG(trace, "ldap_proxy: cannot parse message. Not enough bytes in the buffer.");
    return Decoder::Result::NeedMoreData;
  }

  if (validationResult == Message::ValidationFailed) {
    // Message does not conform to the expected format. Move to out-of-sync state.
    data.drain(data.length());
    state_ = State::OutOfSyncState;
    return Decoder::Result::ReadyForNext;
  }

  // Drain message code and length fields.
  // Processing the message assumes that message starts at the beginning of the buffer.
  data.drain(5);

  processMessageBody(data, msg_processor.direction_, message_len_ - 4, msg, msgParser);

  return Decoder::Result::ReadyForNext;
}
/*
  onDataIgnore method is called when the decoder does not inspect passing
  messages. This happens when the decoder detected encrypted packets or
  when the decoder could not validate passing messages and lost track of
  messages boundaries. In order not to interpret received values as message
  lengths and not to start buffering large amount of data, the decoder
  enters OutOfSync state and starts ignoring passing messages. Once the
  decoder enters OutOfSyncState it cannot leave that state.
*/
Decoder::Result DecoderImpl::onDataIgnore(Buffer::Instance& data, bool) {
  data.drain(data.length());
  return Decoder::Result::ReadyForNext;
}

// Method is called when C (CommandComplete) message has been
// decoded. It extracts the keyword from message's payload
// and updates stats associated with that keyword.
void DecoderImpl::decodeBackendStatements() {
  // The message_ contains the statement. Find space character
  // and the statement is the first word. If space cannot be found
  // try to find for the null terminator character (\0).
  std::size_t position = message_.find(' ');
  if (position == std::string::npos) {
    // If the null terminator character (\0) cannot be found then
    // take the whole message.
    position = message_.find('\0');
  }
  const std::string statement = message_.substr(0, position);

  auto it = BE_statements_.find(statement);
  if (it != BE_statements_.end()) {
    (*it).second(this);
  } else {
    callbacks_->incStatements(DecoderCallbacks::StatementType::Other);
    callbacks_->incTransactions();
    callbacks_->incTransactionsCommit();
  }
}

Decoder::Result DecoderImpl::onDataInNegotiating(Buffer::Instance& data, bool frontend) {
  if (frontend) {
    // No data from downstream is allowed when negotiating upstream SSL
    // with the server.
    data.drain(data.length());
    state_ = State::OutOfSyncState;
    return Decoder::Result::ReadyForNext;
  }

  // This should be reply from the server indicating if it accepted
  // request to use SSL. It is only one character long packet, where
  // 'S' means use SSL, 'E' means do not use.

  // Indicate to the filter, the response and give the initial
  // packet temporarily buffered to be sent upstream.
  bool upstreamSSL = true;
  state_ = State::InitState;
#if 0
  if (data.length() == 1) {
    const char c = data.peekInt<char, ByteOrder::Host, 1>(0);
    if (c == 'S') {
      upstreamSSL = true;
    } else {
      if (c != 'E') {
        state_ = State::OutOfSyncState;
      }
    }
  } else {
    state_ = State::OutOfSyncState;
  }
#endif
  data.drain(data.length());

  if (callbacks_->encryptUpstream(upstreamSSL, temp_storage_)) {
    // FELIX passthrough the message now.
    state_ = State::EncryptedState;
  }

  return Decoder::Result::Stopped;
}

// Method is called when X (Terminate) message
// is encountered by the decoder.
void DecoderImpl::decodeFrontendTerminate() {
  if (session_.inTransaction()) {
    session_.setInTransaction(false);
    callbacks_->incTransactionsRollback();
  }
}

// Method does deep inspection of Authentication message.
// It looks for 4 bytes of zeros, which means that login to
// database was successful.
void DecoderImpl::decodeAuthentication() {
  // Check if auth message indicates successful authentication.
  // Length must be 8 and payload must be 0.
  if ((8 == message_len_) && (0 == message_.data()[0]) && (0 == message_.data()[1]) &&
      (0 == message_.data()[2]) && (0 == message_.data()[3])) {
    incSessionsUnencrypted();
  }
}

// Method is used to parse Error and Notice messages. Their syntax is the same, but they
// use different keywords inside the message and statistics fields are different.
void DecoderImpl::decodeErrorNotice(MsgParserDict& types) {
  // Error/Notice message should start with character "S".
  if (message_[0] != 'S') {
    types.unknown_(this);
    return;
  }

  for (const auto& it : types.keywords_) {
    // Try to find a keyword with S prefix or V prefix.
    // Ldap versions prior to 9.6 use only S prefix while
    // versions higher than 9.6 use S and V prefixes.
    if ((message_.find("S" + it.first) != std::string::npos) ||
        (message_.find("V" + it.first) != std::string::npos)) {
      it.second(this);
      return;
    }
  }

  // Keyword was not found in the message. Count is as Unknown.
  types.unknown_(this);
}

// Method parses E (Error) message and looks for string
// indicating that error happened.
void DecoderImpl::decodeBackendErrorResponse() { decodeErrorNotice(BE_errors_); }

// Method parses N (Notice) message and looks for string
// indicating its meaning. It can be warning, notice, info, debug or log.
void DecoderImpl::decodeBackendNoticeResponse() { decodeErrorNotice(BE_notices_); }

// Method parses Parse message of the following format:
// String: The name of the destination prepared statement (an empty string selects the unnamed
// prepared statement).
//
// String: The query string to be parsed.
//
// Int16: The number of parameter data
// types specified (can be zero). Note that this is not an indication of the number of parameters
// that might appear in the query string, only the number that the frontend wants to pre-specify
// types for. Then, for each parameter, there is the following:
//
// Int32: Specifies the object ID of
// the parameter data type. Placing a zero here is equivalent to leaving the type unspecified.
void DecoderImpl::onParse() {
  // The first two strings are separated by \0.
  // The first string is optional. If no \0 is found it means
  // that the message contains query string only.
  std::vector<std::string> query_parts = absl::StrSplit(message_, absl::ByChar('\0'));
  callbacks_->processQuery(query_parts[1]);
}

void DecoderImpl::onQuery() { callbacks_->processQuery(message_); }

// Method is invoked on clear-text Startup message.
// The message format is continuous string of the following format:
// user<username>database<database-name>application_name<application>encoding<encoding-type>
void DecoderImpl::onStartup() {
  // First 4 bytes of startup message contains version code.
  // It is skipped. After that message contains attributes.
  attributes_ = absl::StrSplit(message_.substr(4), absl::ByChar('\0'), absl::SkipEmpty());

  // If "database" attribute is not found, default it to "user" attribute.
  if ((attributes_.find("database") == attributes_.end()) &&
      (attributes_.find("user") != attributes_.end())) {
    attributes_["database"] = attributes_["user"];
  }
}

// Method generates displayable format of currently processed message.
const std::string DecoderImpl::genDebugMessage(const std::unique_ptr<Message>& parser,
                                               Buffer::Instance& data, uint32_t message_len) {
  parser->read(data, message_len);
  return parser->toString();
}

} // namespace LdapProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
