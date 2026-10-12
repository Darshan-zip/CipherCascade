import copy, pytest
from app.crypto import encrypt_message,decrypt_message,derive_layer_key,generate_sequence,REGISTRY
KEY=b"k"*32
@pytest.mark.parametrize("sequence",[[1],[2],[3],[4],[5],[2,1],[3,2,1],[4,1,5,2],[1,2,3,4,5]])
@pytest.mark.parametrize("message",["", "Hello Bob", "नमस्ते 🔐"])
def test_round_trip(sequence,message):
 p=encrypt_message(message,sequence,"c1","alice",42,KEY)
 assert decrypt_message(p,"c1","alice",KEY)==message
@pytest.mark.parametrize("change",["sequence","number","nonce","ciphertext","tag","conversation"])
def test_tampering_rejected(change):
 p=encrypt_message("secret",[4,1],"c1","alice",42,KEY)
 if change=="sequence":p["algorithm_sequence"]=[1,2]
 elif change=="number":p["message_number"]+=1
 elif change=="nonce":p["layers"][0]["nonce"]="AAAA"
 elif change=="ciphertext":p["layers"][0]["ciphertext"]="AAAA"
 elif change=="tag":p["layers"][0]["tag"]="A"*43
 else:p["conversation_id"]="other"
 with pytest.raises(Exception):decrypt_message(p,"c1","alice",KEY)
def test_unknown_algorithm_rejected():
 with pytest.raises(ValueError):encrypt_message("x",[8],"c1","a",1,KEY)
def test_layer_key_separation():
 assert derive_layer_key(KEY,"c","a",1,0,1)!=derive_layer_key(KEY,"c","a",1,1,1)
def test_random_sequences_use_enabled_registry_and_length_1_to_5():
 for _ in range(200):
  seq=generate_sequence()
  assert 1<=len(seq)<=5
  assert set(seq)<=set(range(1,6))
 assert [entry["status"] for entry in REGISTRY[:5]]==["enabled"]*5
 assert [entry["status"] for entry in REGISTRY[5:]]==["disabled"]*3
