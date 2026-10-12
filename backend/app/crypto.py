"""Experimental authenticated cascade; IDs 1-5 enabled, 6-8 deliberately disabled."""
import base64, json, secrets
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES as PyCryptoAES
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt

REGISTRY_VERSION=2; PROTOCOL_VERSION=2; MAX_PACKET_BYTES=1_048_576; MAX_LAYERS=5
ENABLED={1:("AES-256-GCM",12),2:("ChaCha20-Poly1305",12),3:("XChaCha20-Poly1305",24),4:("AES-256-CTR + HMAC-SHA-256",16),5:("AES-256-GCM independent",12)}
REGISTRY=[
 {"id":1,"name":"AES-256-GCM","construction":"AES-256-GCM","key_bytes":32,"nonce_bytes":12,"authentication":"AEAD tag (16 bytes)","library":"Python cryptography AESGCM / browser Web Crypto","status":"enabled"},
 {"id":2,"name":"ChaCha20-Poly1305","construction":"IETF ChaCha20-Poly1305","key_bytes":32,"nonce_bytes":12,"authentication":"Poly1305 tag (16 bytes)","library":"Python cryptography / browser @noble/ciphers 2.4.0","status":"enabled"},
 {"id":3,"name":"XChaCha20-Poly1305","construction":"XChaCha20-Poly1305","key_bytes":32,"nonce_bytes":24,"authentication":"Poly1305 tag (16 bytes)","library":"Python PyNaCl/libsodium / browser @noble/ciphers 2.4.0","status":"enabled"},
 {"id":4,"name":"AES-256-CTR + HMAC-SHA-256","construction":"Encrypt-then-MAC; separate HKDF keys; MAC over domain || uint32be(aad length) || aad || IV || ciphertext","key_bytes":64,"nonce_bytes":16,"authentication":"HMAC-SHA-256 (32 bytes), verified before decryption","library":"Python cryptography / browser Web Crypto","status":"enabled"},
 {"id":5,"name":"AES-256-GCM comparison","construction":"AES-256-GCM (same cipher as ID 1; implementation comparison only)","key_bytes":32,"nonce_bytes":12,"authentication":"AEAD tag (16 bytes)","library":"Python PyCryptodome 3.24.0 / browser @noble/ciphers 2.4.0","status":"enabled"},
 {"id":6,"name":"Camellia-256 AE","construction":"vetted AE construction not selected","status":"disabled"},
 {"id":7,"name":"Twofish-256 + HMAC-SHA-256","construction":"Encrypt-then-MAC","status":"disabled"},
 {"id":8,"name":"Serpent-256 + HMAC-SHA-256","construction":"Encrypt-then-MAC","status":"disabled"}]
def canonical(value:Any)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def b64(data:bytes)->str: return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def unb64(value:str)->bytes:
 if not isinstance(value,str) or len(value)>1_500_000: raise ValueError("invalid encoding")
 return base64.urlsafe_b64decode(value+"="*(-len(value)%4))
def generate_sequence()->list[int]:
 """Choose a uniform 1-5 length and uniform enabled ID at each position."""
 length=secrets.randbelow(MAX_LAYERS)+1
 return [secrets.choice(tuple(ENABLED)) for _ in range(length)]
def derive_layer_key(session_key:bytes,cid:str,sender:str,number:int,index:int,aid:int)->bytes:
 if aid not in ENABLED: raise ValueError("unsupported algorithm")
 info=canonical(["CipherCascade",PROTOCOL_VERSION,cid,sender,number,index,aid])
 return HKDF(algorithm=hashes.SHA256(),length=64 if aid==4 else 32,salt=None,info=info).derive(session_key)
def _ctr(key,nonce,data,decrypt=False):
 ctx=Cipher(algorithms.AES(key),modes.CTR(nonce)).decryptor() if decrypt else Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
 return ctx.update(data)+ctx.finalize()
def _id4_tag(mac_key,aad,nonce,ciphertext):
 mac=hmac.HMAC(mac_key,hashes.SHA256()); mac.update(b"CipherCascade-v2-ID4-ETM\0"+len(aad).to_bytes(4,"big")+aad+nonce+ciphertext); return mac.finalize()
def _seal(aid,key,nonce,data,aad):
 if aid==1:return AESGCM(key).encrypt(nonce,data,aad),None
 if aid==2:return ChaCha20Poly1305(key).encrypt(nonce,data,aad),None
 if aid==3:return crypto_aead_xchacha20poly1305_ietf_encrypt(data,aad,nonce,key),None
 if aid==4:
  ciphertext=_ctr(key[:32],nonce,data); return ciphertext,_id4_tag(key[32:],aad,nonce,ciphertext)
 if aid==5:
  cipher=PyCryptoAES.new(key,PyCryptoAES.MODE_GCM,nonce=nonce,mac_len=16); cipher.update(aad); encrypted,tag=cipher.encrypt_and_digest(data); return encrypted+tag,None
 raise ValueError("unsupported algorithm")
def _open(aid,key,nonce,data,aad,tag=None):
 if aid==1:return AESGCM(key).decrypt(nonce,data,aad)
 if aid==2:return ChaCha20Poly1305(key).decrypt(nonce,data,aad)
 if aid==3:return crypto_aead_xchacha20poly1305_ietf_decrypt(data,aad,nonce,key)
 if aid==4:
  if tag is None:raise ValueError("missing authentication tag")
  verifier=hmac.HMAC(key[32:],hashes.SHA256()); verifier.update(b"CipherCascade-v2-ID4-ETM\0"+len(aad).to_bytes(4,"big")+aad+nonce+data); verifier.verify(tag)
  return _ctr(key[:32],nonce,data,decrypt=True)
 if aid==5:
  if len(data)<16:raise ValueError("invalid authenticated ciphertext")
  cipher=PyCryptoAES.new(key,PyCryptoAES.MODE_GCM,nonce=nonce,mac_len=16); cipher.update(aad); return cipher.decrypt_and_verify(data[:-16],data[-16:])
 raise ValueError("unsupported algorithm")
def encrypt_message(plaintext:str,sequence:list[int],conversation_id:str,sender_id:str,message_number:int,session_key:bytes)->dict:
 if not isinstance(sequence,list) or not 1<=len(sequence)<=MAX_LAYERS or any(type(a) is not int or a not in ENABLED for a in sequence):raise ValueError("unsupported sequence")
 header={"protocol_version":PROTOCOL_VERSION,"registry_version":REGISTRY_VERSION,"conversation_id":conversation_id,"sender_id":sender_id,"message_number":message_number,"algorithm_sequence":sequence}
 data=plaintext.encode("utf-8"); layers=[]
 for i,aid in enumerate(sequence):
  nonce=secrets.token_bytes(ENABLED[aid][1]); aad=canonical({"header":header,"layer_index":i,"algorithm_id":aid})
  data,tag=_seal(aid,derive_layer_key(session_key,conversation_id,sender_id,message_number,i,aid),nonce,data,aad)
  layers.append({"algorithm_id":aid,"nonce":b64(nonce),"ciphertext":b64(data),**({"tag":b64(tag)} if tag else {})})
 packet={**header,"layers":layers}
 if len(canonical(packet))>MAX_PACKET_BYTES:raise ValueError("packet too large")
 return packet
def decrypt_message(packet:dict,conversation_id:str,sender_id:str,session_key:bytes)->str:
 if len(canonical(packet))>MAX_PACKET_BYTES:raise ValueError("packet too large")
 if packet.get("protocol_version")!=PROTOCOL_VERSION or packet.get("registry_version")!=REGISTRY_VERSION:raise ValueError("unsupported version")
 if packet.get("conversation_id")!=conversation_id or packet.get("sender_id")!=sender_id:raise ValueError("context mismatch")
 seq=packet.get("algorithm_sequence"); layers=packet.get("layers"); number=packet.get("message_number")
 if type(number) is not int or number<0 or not isinstance(seq,list) or not 1<=len(seq)<=MAX_LAYERS or not isinstance(layers,list) or len(layers)!=len(seq):raise ValueError("invalid packet")
 header={k:packet[k] for k in ("protocol_version","registry_version","conversation_id","sender_id","message_number","algorithm_sequence")}; data=None
 for i,(aid,layer) in reversed(list(enumerate(zip(seq,layers)))):
  if aid not in ENABLED or not isinstance(layer,dict) or layer.get("algorithm_id")!=aid:raise ValueError("unsupported or inconsistent layer")
  nonce=unb64(layer.get("nonce")); enc=unb64(layer.get("ciphertext")); tag=unb64(layer["tag"]) if "tag" in layer else None
  if len(nonce)!=ENABLED[aid][1]:raise ValueError("invalid nonce")
  aad=canonical({"header":header,"layer_index":i,"algorithm_id":aid})
  data=_open(aid,derive_layer_key(session_key,conversation_id,sender_id,number,i,aid),nonce,enc,aad,tag)
 return data.decode("utf-8",errors="strict")
