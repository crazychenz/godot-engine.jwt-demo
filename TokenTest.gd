extends Control

# Number of seconds for token to remain valid.
var duration : int = 30
var private_key : CryptoKey = CryptoKey.new()
var public_key : CryptoKey = CryptoKey.new()


var state = {
	"hs256_token": "",
	"hs256_header": "",
	"hs256_payload": "",
	"hs256_secret": "",
	"rs256_token": "",
	"rs256_header": "",
	"rs256_payload": "",
	"rs256_public_key": "",
	"rs256_private_key": "",
}


func _is_state_updated():
	return \
		find_node("PublicKeyPEM").text == state.public_key && \
		find_node("PrivateKeyPEM").text == state.private_key && \
		find_node("Secret").text == state.hs256_secret && \
		find_node("RS256Token").text == state.rs256_token && \
		find_node("RS256Payload").text == state.rs256_payload && \
		find_node("RS256Header").text == state.rs256_header && \
		find_node("HS256Token").text == state.hs256_token && \
		find_node("HS256Payload").text == state.hs256_payload && \
		find_node("HS256Header").text == state.hs256_header
		


func _sync_state():
	state.public_key = find_node("PublicKeyPEM").text
	state.private_key = find_node("PrivateKeyPEM").text
	state.rs256_token = find_node("RS256Token").text
	state.hs256_token = find_node("HS256Token").text
	state.rs256_payload = find_node("RS256Payload").text
	state.rs256_header = find_node("RS256Header").text
	state.hs256_payload = find_node("HS256Payload").text
	state.hs256_header = find_node("HS256Header").text
	state.hs256_secret = find_node("Secret").text
	public_key.load_from_string(find_node("PublicKeyPEM").text, true)
	private_key.load_from_string(find_node("PrivateKeyPEM").text, false)


func _json_stringify(obj):
	var json : JSON = JSON.new()
	return json.stringify(obj)

func _json_parse(data) -> Dictionary:
	var json : JSON = JSON.new()
	if json.parse(data) != OK:
		return {}
	return json.get_data()


func _init_fields():
	# Populate fields
	var crypto = Crypto.new()
	var key : CryptoKey = crypto.generate_rsa(4096)
	find_node("PrivateKeyPEM").text = key.save_to_string(false)
	find_node("PublicKeyPEM").text = key.save_to_string(true)
	find_node("Secret").text = "secret"
	public_key.load_from_string(find_node("PublicKeyPEM").text, true)
	private_key.load_from_string(find_node("PrivateKeyPEM").text, false)
	
	var exp_time = int(Time.get_unix_time_from_system()) + duration
	
	var hs256_alg = JWTAlgorithmBuilder.HS256(find_node("Secret").text)
	var hs256_builder: JWTBuilder = JWT.create(hs256_alg) \
		.with_expires_at(exp_time) \
		.with_issuer("Godot") \
		.with_claim("id","someid")
	find_node("HS256Header").text = _json_stringify(hs256_builder.header_claims)
	find_node("HS256Payload").text = _json_stringify(hs256_builder.payload_claims)
	
	var rs256_alg = JWTAlgorithmBuilder.RSA256(public_key, private_key)
	var rs256_builder: JWTBuilder = JWT.create(rs256_alg) \
		.with_expires_at(exp_time) \
		.with_issuer("Godot") \
		.with_claim("id","someid")
	find_node("RS256Header").text = _json_stringify(rs256_builder.header_claims)
	find_node("RS256Payload").text = _json_stringify(rs256_builder.payload_claims)
	
	find_node("RS256Token").text = rs256_builder.sign(rs256_alg)
	find_node("HS256Token").text = hs256_builder.sign(hs256_alg)
	
	_sync_state()
	
	do_verify()


func _ready():
	
	_init_fields()
	
	find_node("PublicKeyPEM").connect("focus_exited", self.data_updated)
	find_node("PrivateKeyPEM").connect("focus_exited", self.data_updated)
	find_node("Secret").connect("focus_exited", self.data_updated)
	
	find_node("HS256Token").connect("focus_exited", self.token_updated)
	find_node("HS256Header").connect("focus_exited", self.data_updated)
	find_node("HS256Payload").connect("focus_exited", self.data_updated)
	
	find_node("RS256Token").connect("focus_exited", self.token_updated)
	find_node("RS256Header").connect("focus_exited", self.data_updated)
	find_node("RS256Payload").connect("focus_exited", self.data_updated)


func token_updated():
	if _is_state_updated():
		return
	_sync_state()
	
	do_decode()
	do_verify()
	_sync_state()
	
	


func data_updated():
	if _is_state_updated():
		return
	_sync_state()
	
	do_sign()
	do_verify()
	_sync_state()


func do_decode():
	var rs256_decoder: JWTDecoder = JWT.decode(find_node("RS256Token").text)
	find_node("RS256Header").text = _json_stringify(rs256_decoder.header_claims)
	find_node("RS256Payload").text = _json_stringify(rs256_decoder.payload_claims)
	
	var hs256_decoder: JWTDecoder = JWT.decode(find_node("HS256Token").text)
	find_node("HS256Header").text = _json_stringify(hs256_decoder.header_claims)
	find_node("HS256Payload").text = _json_stringify(hs256_decoder.payload_claims)


func do_verify():
	# Do a verification
	var rs256_verifier: JWTVerifier = JWT.require(JWTAlgorithmBuilder.RSA256(public_key)) \
		.build() # Reusable Verifier
	if rs256_verifier.verify(state.rs256_token) == JWTVerifier.JWTExceptions.OK:
		find_node("RS256Verification").text = "Token Verified with RS256"
	else:
		find_node("RS256Verification").text = rs256_verifier.exception
	
	var hs256_verifier: JWTVerifier = JWT.require(JWTAlgorithmBuilder.HSA256(state.hs256_secret)) \
		.build() # Reusable Verifier
	if hs256_verifier.verify(state.hs256_token) == JWTVerifier.JWTExceptions.OK:
		find_node("HS256Verification").text = "Token Verified with HS256"
	else:
		find_node("HS256Verification").text = rs256_verifier.exception


func do_sign():
	var rs256_alg : JWTAlgorithm = JWTAlgorithmBuilder.RSA256(public_key, private_key)
	var rs256_builder: JWTBuilder = JWT.create(rs256_alg, _json_parse(state.rs256_header), _json_parse(state.rs256_payload))
	find_node("RS256Token").text = rs256_builder.sign(rs256_alg)
	
	var hs256_alg : JWTAlgorithm = JWTAlgorithmBuilder.HSA256(state.hs256_secret)
	var hs256_builder: JWTBuilder = JWT.create(hs256_alg, _json_parse(state.hs256_header), _json_parse(state.hs256_payload))
	find_node("HS256Token").text = hs256_builder.sign(hs256_alg)


