import { FormEvent, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Check, LockKeyhole, LogIn, LogOut, MessageCircle, Plus, Send, Shield, Sun, Moon, Copy } from 'lucide-react';
import { decryptMessage, encryptMessage, randomSequence, REGISTRY, AlgorithmId } from './crypto';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
type User = { id: string; username: string };
type Conv = { id: string; participants: User[] };
type Msg = { message_id: string; sender_id: string; packet: any; created_at: string; plain: string; authenticated: boolean };

export default function App() {
  const [token, setToken] = useState(localStorage.token || '');
  const [user, setUser] = useState<User | null>(() => { try { return JSON.parse(localStorage.user || 'null'); } catch { return null; } });
  const [conversations, setConversations] = useState<Conv[]>([]);
  const [active, setActive] = useState('');
  const [messages, setMessages] = useState<Msg[]>([]);
  const [secret, setSecret] = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [message, setMessage] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [invite, setInvite] = useState('');
  const [inviteOut, setInviteOut] = useState('');
  const [error, setError] = useState('');
  const [panel, setPanel] = useState('');
  const [dark, setDark] = useState(true);
  const [busy, setBusy] = useState(false);
  const bottom = useRef<HTMLDivElement>(null);
  const req = async (path: string, method = 'GET', body?: unknown) => {
    const response = await fetch(API + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  };
  const loadConversations = async () => {
    if (!token) return;
    try { const items = await req('/api/conversations'); setConversations(items); if (!active && items.length) setActive(items[0].id); }
    catch (e) { setError((e as Error).message); }
  };
  useEffect(() => { void loadConversations(); }, [token]);
  useEffect(() => {
    if (!active || !unlocked) return;
    let cancelled = false;
    const loadMessages = async () => {
      try {
        const rows = await req(`/api/conversations/${active}/messages`);
        const result: Msg[] = [];
        for (const row of rows) {
          try { result.push({ ...row, plain: await decryptMessage(row.packet, active, row.sender_id, secret), authenticated: true }); }
          catch (e) { console.warn('CipherCascade packet rejected:', e instanceof Error ? `${e.name}: ${e.message}` : 'invalid packet'); result.push({ ...row, plain: 'Unable to authenticate this message', authenticated: false }); }
        }
        if (!cancelled) setMessages(result);
      } catch (e) { if (!cancelled) setError((e as Error).message); }
    };
    void loadMessages(); const timer = window.setInterval(loadMessages, 5000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [active, unlocked, secret, token]);
  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const authenticate = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await fetch(`${API}/api/${authMode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'Unable to sign in');
      localStorage.token = data.token; localStorage.user = JSON.stringify(data.user); setToken(data.token); setUser(data.user);
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const createConversation = async () => {
    try { const result = await req('/api/conversations', 'POST'); setInviteOut(result.invite_code); await loadConversations(); setActive(result.id); setUnlocked(false); setSecret(''); }
    catch (e) { setError((e as Error).message); }
  };
  const joinConversation = async () => {
    try { const result = await req('/api/conversations/join', 'POST', { code: invite }); setInvite(''); await loadConversations(); setActive(result.id); setUnlocked(false); setSecret(''); }
    catch (e) { setError((e as Error).message); }
  };
  const sendMessage = async (event: FormEvent) => {
    event.preventDefault(); if (!message.trim() || !active || !user || !unlocked) return;
    try {
      const sequence = randomSequence(); const number = Date.now();
      const packet = await encryptMessage(message, sequence, active, user.id, number, secret);
      await req(`/api/conversations/${active}/messages`, 'POST', { message_id: crypto.randomUUID(), packet });
      setMessage('');
      const rows = await req(`/api/conversations/${active}/messages`); const result: Msg[] = [];
      for (const row of rows) {
        try { result.push({ ...row, plain: await decryptMessage(row.packet, active, row.sender_id, secret), authenticated: true }); }
        catch (e) { console.warn('CipherCascade packet rejected:', e instanceof Error ? `${e.name}: ${e.message}` : 'invalid packet'); result.push({ ...row, plain: 'Unable to authenticate this message', authenticated: false }); }
      }
      setMessages(result);
    } catch (e) { setError((e as Error).message); }
  };
  const selectedConversation = conversations.find(c => c.id === active);
  const other = (c: Conv) => c.participants.find(p => p.id !== user?.id)?.username || 'Conversation';

  if (!token) return <main className="auth"><div className="auth-card"><Logo/><p className="eyebrow">PRIVATE MESSAGING PROTOTYPE</p><h1>{authMode === 'login' ? 'Welcome back' : 'Create your account'}</h1><p className="muted">Messages are encrypted in your browser before they reach the relay.</p><form onSubmit={authenticate}><label>Username<input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required minLength={3}/></label><label>Password<input type="password" autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={e => setPassword(e.target.value)} required minLength={12}/></label><button className="primary full" disabled={busy}>{busy ? 'Working…' : authMode === 'login' ? 'Sign in' : 'Register'}</button></form>{error && <p className="error">{error}</p>}<button className="link" onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}>{authMode === 'login' ? 'Create an account' : 'Already registered? Sign in'}</button><div className="local-note"><AlertTriangle size={15}/> Experimental protocol. Do not use for sensitive communications.</div></div></main>;

  return <div className={dark ? 'app dark' : 'app'}>
    <aside className="sidebar"><div className="brand"><Logo/><button className="icon" aria-label="Toggle theme" onClick={() => setDark(!dark)}>{dark ? <Sun size={17}/> : <Moon size={17}/>}</button></div>
      <div className="side-label">YOUR CONVERSATIONS <button className="icon" onClick={createConversation} aria-label="Create conversation"><Plus size={17}/></button></div>
      <div className="conversation-list">{conversations.map((c, i) => <button className={`conversation ${active === c.id ? 'selected' : ''}`} key={c.id} onClick={() => { setActive(c.id); setUnlocked(false); setSecret(''); setMessages([]); }}><span className="avatar">{other(c)[0]?.toUpperCase() || '?'}</span><span className="conv-text"><b>{other(c)}</b><small>{c.participants.length}/2 participants</small></span><span className="online-dot"/></button>)}</div>
      <div className="side-actions"><div className="join-row"><input placeholder="Invitation code" value={invite} onChange={e => setInvite(e.target.value)}/><button className="icon" onClick={joinConversation} aria-label="Join conversation"><LogIn size={16}/></button></div><button className="secondary full" onClick={createConversation}><Plus size={15}/> New conversation</button></div>
      <div className="profile"><span className="avatar self">{user?.username[0]?.toUpperCase()}</span><span><b>{user?.username}</b><small>Signed in</small></span><button className="icon" aria-label="Sign out" onClick={() => { localStorage.clear(); setToken(''); setUser(null); }}><LogOut size={16}/></button></div>
    </aside>
    <main className="main"><header className="topbar"><div className="peer"><span className="avatar">{selectedConversation ? other(selectedConversation)[0]?.toUpperCase() : '?'}</span><div><b>{selectedConversation ? other(selectedConversation) : 'Select a conversation'}</b><small><span className="online-dot"/> Relay history · five-second polling</small></div></div><button className={`security-toggle ${panel ? 'active' : ''}`} onClick={() => setPanel(panel ? '' : 'security')}><Shield size={16}/> Security details</button></header>
      {inviteOut && <div className="invite-banner"><span><b>Share this invite code with your contact</b><code>{inviteOut}</code></span><button className="icon" onClick={() => navigator.clipboard.writeText(inviteOut)} aria-label="Copy invitation"><Copy size={16}/></button><button className="icon" onClick={() => setInviteOut('')} aria-label="Dismiss"><Check size={16}/></button></div>}
      <div className="body"><section className="chat"><div className="chat-scroll">
        {!selectedConversation ? <div className="empty"><div className="empty-icon"><MessageCircle size={25}/></div><h2>Your private space</h2><p>Create a conversation or join with an invite code to start.</p><button className="primary" onClick={createConversation}><Plus size={16}/> Create conversation</button></div>
          : !unlocked ? <div className="setup"><div className="setup-icon"><LockKeyhole size={22}/></div><p className="eyebrow">LOCAL KEY SETUP</p><h2>Agree on a shared secret</h2><p>Both participants must enter the exact same phrase. It stays in this browser and is not sent to the relay. This is not authenticated key exchange.</p><label>Shared secret<input type="password" value={secret} onChange={e => setSecret(e.target.value)} placeholder="Use a long, unique phrase"/></label><button className="primary" disabled={secret.length < 16} onClick={() => setUnlocked(true)}>Unlock conversation <LockKeyhole size={15}/></button></div>
          : messages.length === 0 ? <div className="empty small-empty"><div className="empty-icon"><Shield size={24}/></div><h2>Encrypted conversation</h2><p>Each message gets a secure random sequence of one to five algorithms.</p></div>
          : <>{messages.map(m => <article className={`message-row ${m.sender_id === user?.id ? 'mine' : ''}`} key={m.message_id}><div className="message"><div className="message-meta"><b>{m.sender_id === user?.id ? 'You' : selectedConversation.participants.find(p => p.id === m.sender_id)?.username || 'Participant'}</b><time>{new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time><button className="inspect" onClick={() => setPanel(panel === m.message_id ? '' : m.message_id)} title="Inspect packet"><Shield size={13}/></button></div><p>{m.plain}</p>{panel === m.message_id && <div className="inline-security">{m.authenticated ? <>Authenticated <Check size={13}/></> : <>Rejected <AlertTriangle size={13}/></>}</div>}</div></article>)}<div ref={bottom}/></>}
      </div>
      {selectedConversation && unlocked && <form className="composer" onSubmit={sendMessage}><textarea aria-label="Message" placeholder="Write an encrypted message…" value={message} onChange={e => setMessage(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form?.requestSubmit(); } }}/><div className="composer-foot"><span><LockKeyhole size={13}/> Encrypted locally · random 1–5 algorithm cascade</span><div><span className="layer-select">CSPRNG selects sequence for each message</span><button className="send" aria-label="Send message" disabled={!message.trim()}><Send size={16}/></button></div></div></form>}
      </section>{panel && <SecurityPanel conversation={selectedConversation} ready={unlocked} selected={messages.find(m => m.message_id === panel) ?? (panel === 'security' ? messages[messages.length - 1] : undefined)}/>}</div>
    </main>{error && <div className="toast" role="alert">{error}<button onClick={() => setError('')}>×</button></div>}
  </div>;
}

function Logo() { return <div className="logo"><span><Shield size={19}/></span><b>Cipher<span>Cascade</span></b></div>; }
function SecurityPanel({ conversation, ready, selected }: { conversation?: Conv; ready: boolean; selected?: Msg }) {
  const sequence = Array.isArray(selected?.packet?.algorithm_sequence) ? selected.packet.algorithm_sequence.filter((id: unknown): id is AlgorithmId => typeof id === 'number' && Object.hasOwn(REGISTRY, id)) : [];
  return <aside className="security"><div className="security-head"><div><p className="eyebrow">INSPECTION</p><h3>Security details</h3></div><Shield size={17}/></div>
    {!conversation ? <p className="muted">Choose a conversation to inspect its security status.</p> : <>
      <div className="status-card"><span className={selected && !selected.authenticated ? 'check-ring failed' : 'check-ring'}>{selected && !selected.authenticated ? <AlertTriangle size={14}/> : <Check size={14}/>}</span><span><b>{selected ? (selected.authenticated ? 'Packet authenticated' : 'Packet rejected') : 'Encryption active'}</b><small>{ready ? 'Local checks complete' : 'Shared secret required'}</small></span></div>
      <div className="inspect-section"><h4>Session</h4><div className="detail"><span>Conversation</span><code>{conversation.id.slice(0, 12)}…</code></div><div className="detail"><span>Participants</span><b>{conversation.participants.length} / 2</b></div><div className="detail"><span>Key exchange</span><b className="warn-text">Manual phrase</b></div><div className="detail"><span>Forward secrecy</span><b className="warn-text">Not provided</b></div></div>
      {selected ? <div className="inspect-section"><h4>Selected message</h4><div className="detail"><span>Message number</span><b>#{selected.packet?.message_number ?? '—'}</b></div><div className="detail"><span>Protocol</span><b>{selected.packet?.protocol_version ? `v${selected.packet.protocol_version}` : 'Unknown'}</b></div><div className="detail"><span>Transmitted sequence</span><code>{sequence.length ? `[${sequence.join(', ')}]` : 'Unavailable (legacy or invalid packet)'}</code></div>{sequence.length > 0 && <><div className="sequence"><small>ALGORITHM BY SEQUENCE ID</small>{sequence.map((id: AlgorithmId, i: number) => <div className="detail" key={i}><span>Layer {i + 1} · ID {id}</span><b>{REGISTRY[id].name}</b></div>)}</div><div className="sequence"><small>ENCRYPTION ORDER</small><div>{sequence.map((id: AlgorithmId, i: number) => <span key={i}>ID {id} · {REGISTRY[id].name}{i < sequence.length - 1 ? ' → ' : ''}</span>)}</div></div><div className="sequence"><small>DECRYPTION ORDER</small><div>{[...sequence].reverse().map((id: AlgorithmId, i: number) => <span key={i}>ID {id} · {REGISTRY[id].name}{i < sequence.length - 1 ? ' → ' : ''}</span>)}</div></div></>}<div className="detail"><span>Authentication</span><b className={selected.authenticated ? 'good' : 'warn-text'}>{selected.authenticated ? 'VALID' : 'FAILED'}</b></div><div className="detail"><span>Decryption</span><b className={selected.authenticated ? 'good' : 'warn-text'}>{selected.authenticated ? 'SUCCESS' : 'FAILED'}</b></div></div>
        : <div className="inspect-section"><h4>Enabled registry</h4>{Object.entries(REGISTRY).map(([id, item]) => <div className="alg-row" key={id}><span className="alg-dot"/>{item.name}<small>ID {id}</small></div>)}<div className="detail"><span>Disabled</span><b className="warn-text">IDs 6–8</b></div></div>}
      <div className="key-hidden"><LockKeyhole size={14}/><span>Message keys <b>HIDDEN</b></span></div><div className="caution"><AlertTriangle size={15}/><p>Experimental protocol; no independent review. ID 5 repeats AES-GCM for implementation comparison.</p></div>
    </>}
  </aside>;
}
