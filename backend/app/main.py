"""Untrusted encrypted-packet relay. This prototype uses local SQLite by default."""
import hashlib, hmac, json, os, secrets, time
from datetime import datetime, timezone
from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from .crypto import REGISTRY, REGISTRY_VERSION, PROTOCOL_VERSION, MAX_PACKET_BYTES, MAX_LAYERS, ENABLED, canonical

DATABASE_URL=os.getenv("DATABASE_URL","sqlite:///./ciphercascade.db")
APP_SECRET=os.getenv("APP_SECRET","local-development-only-change-this-secret-32-bytes")
engine=create_engine(DATABASE_URL,connect_args={"check_same_thread":False} if DATABASE_URL.startswith("sqlite") else {},pool_pre_ping=True)
SessionLocal=sessionmaker(engine,expire_on_commit=False)
class Base(DeclarativeBase): pass
class User(Base):
 __tablename__="users"
 id:Mapped[str]=mapped_column(String(36),primary_key=True); username:Mapped[str]=mapped_column(String(64),unique=True); password_hash:Mapped[str]=mapped_column(String(256))
class Conversation(Base):
 __tablename__="conversations"
 id:Mapped[str]=mapped_column(String(36),primary_key=True); invite_hash:Mapped[str]=mapped_column(String(64),unique=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class Member(Base):
 __tablename__="members"; __table_args__=(UniqueConstraint("conversation_id","user_id"),)
 id:Mapped[int]=mapped_column(primary_key=True,autoincrement=True); conversation_id:Mapped[str]=mapped_column(ForeignKey("conversations.id")); user_id:Mapped[str]=mapped_column(ForeignKey("users.id"))
class Message(Base):
 __tablename__="messages"; __table_args__=(UniqueConstraint("conversation_id","message_id"),)
 id:Mapped[int]=mapped_column(primary_key=True,autoincrement=True); conversation_id:Mapped[str]=mapped_column(ForeignKey("conversations.id"),index=True); message_id:Mapped[str]=mapped_column(String(80)); sender_id:Mapped[str]=mapped_column(ForeignKey("users.id")); packet:Mapped[str]=mapped_column(Text); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
Base.metadata.create_all(engine)
def db():
 s=SessionLocal()
 try: yield s
 finally: s.close()
def pwd_hash(p,salt=None):
 salt=salt or secrets.token_bytes(16); return salt.hex()+"$"+hashlib.pbkdf2_hmac("sha256",p.encode(),salt,310_000).hex()
def issue(uid):
 body=f"{uid}.{int(time.time())+86400}"; return body+"."+hmac.new(APP_SECRET.encode(),body.encode(),hashlib.sha256).hexdigest()
def current(authorization:Annotated[str|None,Header()]=None,s:Session=Depends(db))->User:
 try:
  scheme,token=authorization.split(" ",1); uid,exp,sig=token.rsplit(".",2); body=f"{uid}.{exp}"
  if scheme.lower()!="bearer" or int(exp)<int(time.time()) or not hmac.compare_digest(sig,hmac.new(APP_SECRET.encode(),body.encode(),hashlib.sha256).hexdigest()):raise ValueError()
  user=s.get(User,uid)
  if not user:raise ValueError()
  return user
 except Exception:raise HTTPException(401,"authentication required")
class Credentials(BaseModel):
 username:str=Field(min_length=3,max_length=64,pattern=r"^[A-Za-z0-9_.-]+$")
 password:str=Field(min_length=12,max_length=256)
class Invite(BaseModel): code:str=Field(min_length=16,max_length=128)
class PacketInput(BaseModel): message_id:str=Field(min_length=1,max_length=80); packet:dict
app=FastAPI(title="CipherCascade Relay",version="0.1.0")
app.add_middleware(CORSMiddleware,allow_origins=[os.getenv("FRONTEND_ORIGIN","http://localhost:5173")],allow_credentials=True,allow_methods=["GET","POST"],allow_headers=["Authorization","Content-Type"])
@app.get("/health")
def health():return {"status":"ok"}
@app.get("/api/registry")
def registry():return {"version":REGISTRY_VERSION,"algorithms":REGISTRY,"protocol_version":PROTOCOL_VERSION}
@app.post("/api/register")
def register(data:Credentials,s:Session=Depends(db)):
 if s.scalar(select(User).where(User.username==data.username)):raise HTTPException(409,"username unavailable")
 u=User(id=secrets.token_hex(16),username=data.username,password_hash=pwd_hash(data.password));s.add(u);s.commit();return {"token":issue(u.id),"user":{"id":u.id,"username":u.username}}
@app.post("/api/login")
def login(data:Credentials,s:Session=Depends(db)):
 u=s.scalar(select(User).where(User.username==data.username))
 if not u:raise HTTPException(401,"invalid credentials")
 salt,expected=u.password_hash.split("$");actual=pwd_hash(data.password,bytes.fromhex(salt)).split("$")[1]
 if not hmac.compare_digest(expected,actual):raise HTTPException(401,"invalid credentials")
 return {"token":issue(u.id),"user":{"id":u.id,"username":u.username}}
@app.post("/api/conversations")
def create_conversation(u:User=Depends(current),s:Session=Depends(db)):
 if len(s.scalars(select(Member).where(Member.user_id==u.id)).all())>=100:raise HTTPException(429,"conversation limit reached")
 code=secrets.token_urlsafe(24);c=Conversation(id=secrets.token_hex(16),invite_hash=hashlib.sha256(code.encode()).hexdigest());s.add(c);s.flush();s.add(Member(conversation_id=c.id,user_id=u.id));s.commit();return {"id":c.id,"invite_code":code,"participants":1}
@app.post("/api/conversations/join")
def join_conversation(data:Invite,u:User=Depends(current),s:Session=Depends(db)):
 c=s.scalar(select(Conversation).where(Conversation.invite_hash==hashlib.sha256(data.code.encode()).hexdigest()))
 if not c:raise HTTPException(404,"invitation unavailable")
 members=s.scalars(select(Member).where(Member.conversation_id==c.id)).all()
 if any(m.user_id==u.id for m in members):return {"id":c.id}
 if len(members)>=2:raise HTTPException(409,"conversation is full")
 s.add(Member(conversation_id=c.id,user_id=u.id));s.commit();return {"id":c.id}
def authorized(cid,u,s):
 if not s.scalar(select(Member).where(Member.conversation_id==cid,Member.user_id==u.id)):raise HTTPException(403,"conversation unavailable")
@app.get("/api/conversations")
def conversations(u:User=Depends(current),s:Session=Depends(db)):
 ids=[m.conversation_id for m in s.scalars(select(Member).where(Member.user_id==u.id)).all()]
 result=[]
 for c in s.scalars(select(Conversation).where(Conversation.id.in_(ids))).all():
  members=s.scalars(select(Member).where(Member.conversation_id==c.id)).all();result.append({"id":c.id,"participants":[{"id":m.user_id,"username":s.get(User,m.user_id).username} for m in members]})
 return result
@app.get("/api/conversations/{cid}/messages")
def history(cid:str,limit:int=100,u:User=Depends(current),s:Session=Depends(db)):
 authorized(cid,u,s);rows=s.scalars(select(Message).where(Message.conversation_id==cid).order_by(Message.id.desc()).limit(min(max(limit,1),200))).all()
 return [{"message_id":m.message_id,"sender_id":m.sender_id,"packet":json.loads(m.packet),"created_at":m.created_at.isoformat()} for m in reversed(rows)]
@app.post("/api/conversations/{cid}/messages")
def send(cid:str,data:PacketInput,u:User=Depends(current),s:Session=Depends(db)):
 authorized(cid,u,s)
 if len(canonical(data.packet))>MAX_PACKET_BYTES:raise HTTPException(413,"packet too large")
 if data.packet.get("conversation_id")!=cid or data.packet.get("sender_id")!=u.id:raise HTTPException(400,"packet context mismatch")
 seq=data.packet.get("algorithm_sequence");layers=data.packet.get("layers")
 if data.packet.get("protocol_version")!=PROTOCOL_VERSION or data.packet.get("registry_version")!=REGISTRY_VERSION or not isinstance(seq,list) or not 1<=len(seq)<=MAX_LAYERS or not isinstance(layers,list) or len(layers)!=len(seq) or any(type(a) is not int or a not in ENABLED for a in seq) or any(not isinstance(layer,dict) or layer.get("algorithm_id")!=aid for aid,layer in zip(seq,layers)):
  raise HTTPException(400,"invalid packet sequence")
 if type(data.packet.get("message_number")) is not int or data.packet["message_number"]<0:raise HTTPException(400,"invalid message number")
 try:s.add(Message(conversation_id=cid,message_id=data.message_id,sender_id=u.id,packet=json.dumps(data.packet,separators=(",",":"))));s.commit()
 except Exception:s.rollback();raise HTTPException(409,"duplicate message")
 return {"status":"stored","message_id":data.message_id}
@app.websocket("/ws/{cid}")
async def websocket(ws:WebSocket,cid:str,token:str):
 await ws.accept()
 try:
  body=token.rsplit(".",1)[0];uid,exp=body.rsplit(".",1);sig=token.rsplit(".",1)[1]
  if int(exp)<int(time.time()) or not hmac.compare_digest(sig,hmac.new(APP_SECRET.encode(),body.encode(),hashlib.sha256).hexdigest()):raise ValueError()
  with SessionLocal() as s:authorized(cid,s.get(User,uid),s)
  await ws.send_json({"type":"ready"})
  while True:
   raw=await ws.receive_json()
   if raw.get("type")=="ping":await ws.send_json({"type":"pong"})
   else:await ws.send_json({"type":"error","error":"Live fanout is not implemented; use packet history."})
 except (WebSocketDisconnect,Exception):
  try:await ws.close(code=1008)
  except Exception:pass
