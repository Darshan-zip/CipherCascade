import secrets, pytest
from fastapi import HTTPException
from app.main import SessionLocal, Credentials, Invite, PacketInput, register, create_conversation, join_conversation, send, history, authorized, User

def test_room_invite_authorization_and_opaque_packet():
 with SessionLocal() as s:
  def account():
   name="u"+secrets.token_hex(6)
   result=register(Credentials(username=name,password="correct horse battery staple"),s)
   return s.get(User,result["user"]["id"])
  alice=account();bob=account();mallory=account()
  room=create_conversation(alice,s)
  joined=join_conversation(Invite(code=room["invite_code"]),bob,s)
  assert joined["id"]==room["id"]
  with pytest.raises(HTTPException) as full:join_conversation(Invite(code=room["invite_code"]),mallory,s)
  assert full.value.status_code==409
  packet={"protocol_version":2,"registry_version":2,"conversation_id":room["id"],"sender_id":alice.id,"message_number":1,"algorithm_sequence":[1],"layers":[{"algorithm_id":1,"nonce":"abc","ciphertext":"opaque-bytes"}]}
  send(room["id"],PacketInput(message_id="packet-"+secrets.token_hex(5),packet=packet),alice,s)
  assert history(room["id"],100,bob,s)[0]["packet"]==packet
  with pytest.raises(HTTPException) as denied:authorized(room["id"],mallory,s)
  assert denied.value.status_code==403
  forged={**packet,"sender_id":bob.id}
  with pytest.raises(HTTPException) as mismatch:send(room["id"],PacketInput(message_id="packet-"+secrets.token_hex(5),packet=forged),alice,s)
  assert mismatch.value.status_code==400
  unsupported={**packet,"algorithm_sequence":[6],"layers":[{"algorithm_id":6,"nonce":"x","ciphertext":"x"}]}
  with pytest.raises(HTTPException) as invalid:send(room["id"],PacketInput(message_id="packet-"+secrets.token_hex(5),packet=unsupported),alice,s)
  assert invalid.value.status_code==400
