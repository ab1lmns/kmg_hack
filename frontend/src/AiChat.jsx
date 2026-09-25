import { useEffect, useRef, useState } from 'react'
import { api } from './api.js'

const suggestions = [
  { label: 'Что исправить первым?', question: 'Какие 3 риска из текущего анализа исправить в первую очередь и почему?' },
  { label: 'Объясни Security Score', question: 'Объясни текущий AD Security Score и какие находки сильнее всего влияют на него.' },
  { label: 'Помоги с сайтом', question: 'Как пользоваться разделами этого сайта и где посмотреть причины риска?' },
]

function InlineText({ text }) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean).map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>
    return part
  })
}

function MessageText({ text }) {
  return <div className="ai-chat-prose">{text.split('\n').map((raw, index) => {
    const line = raw.trim()
    if (!line) return <div className="ai-chat-gap" key={index}/>
    const bullet = line.match(/^[-*]\s+(.+)/)
    const numbered = line.match(/^(\d+)\.\s+(.+)/)
    if (bullet || numbered) return <div className="ai-chat-list-line" key={index}><span>{bullet ? '•' : `${numbered[1]}.`}</span><div><InlineText text={bullet ? bullet[1] : numbered[2]}/></div></div>
    const heading = line.match(/^#{1,3}\s+(.+)/)
    return <p className={heading ? 'ai-chat-prose-heading' : ''} key={index}><InlineText text={heading ? heading[1] : line}/></p>
  })}</div>
}

export default function AiChat({ page, scanId, scannedAt, score, findingCount }) {
  const [open, setOpen] = useState(false)
  const [configured, setConfigured] = useState(null)
  const [messages, setMessages] = useState([])
  const [draft, setDraft] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')
  const endRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    let mounted = true
    api('/ai/status').then(result => { if (mounted) setConfigured(result.configured) })
      .catch(() => { if (mounted) setConfigured(false) })
    return () => { mounted = false }
  }, [])
  useEffect(() => { setMessages([]); setError('') }, [scanId])
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }) }, [messages, sending, open])
  useEffect(() => { if (open) inputRef.current?.focus() }, [open])

  async function send(event, suggested) {
    event?.preventDefault()
    const question = (suggested ?? draft).trim()
    if (!question || sending || !configured) return
    const history = messages.map(({ role, content }) => ({ role, content })).slice(-12)
    setDraft(''); setError(''); setSending(true)
    setMessages(previous => [...previous, { role: 'user', content: question }])
    try {
      const result = await api('/ai/chat', { method: 'POST', body: JSON.stringify({ message: question, history, page }) })
      setMessages(previous => [...previous, { role: 'assistant', content: result.answer }])
    } catch (caught) {
      setMessages(previous => previous.slice(0, -1))
      setDraft(question)
      setError(caught.message)
    } finally {
      setSending(false)
    }
  }

  const scanTime = scannedAt ? new Date(scannedAt).toLocaleString('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : null

  return <div className="ai-chat-root">
    {open && <section className="ai-chat-panel" aria-label="ИИ-помощник">
      <header className="ai-chat-head">
        <div className="ai-chat-identity"><h2>Помощник</h2><p>Вопросы по анализу и работе с сайтом</p></div>
        <button type="button" className="ai-chat-close" onClick={() => setOpen(false)} aria-label="Закрыть чат">×</button>
      </header>

      <div className="ai-chat-context"><div><strong>{scanTime ? `Анализ от ${scanTime}` : 'Нет сохранённого анализа'}</strong><small>{scanId ? `Security Score ${score ?? '—'}/100 · ${findingCount ?? '—'} находок` : 'Запустите анализ для вопросов по домену'}</small></div><span className="ai-chat-context-status">{configured === null ? 'Проверка' : configured ? 'Готов' : 'Нужна настройка'}</span></div>

      <div className="ai-chat-body" role="log" aria-live="polite">
        {messages.length === 0 && <div className="ai-chat-intro"><h3>Чем помочь?</h3><p>Спросите о рисках, оценке или разделах сайта.</p></div>}
        {!configured && configured !== null && <div className="ai-chat-setup">Добавьте <code>OPENAI_API_KEY</code> в <code>backend/.env</code> и перезапустите проект, чтобы задавать вопросы.</div>}
        {configured && messages.length === 0 && <div className="ai-chat-suggestions">{suggestions.map(item => <button type="button" key={item.label} onClick={() => send(null, item.question)}>{item.label}</button>)}</div>}
        {messages.map((item, index) => <div key={index} className={`ai-chat-message ai-chat-${item.role}`}><div className="ai-chat-message-label">{item.role === 'assistant' ? 'Помощник' : 'Вы'}</div><div className="ai-chat-bubble"><MessageText text={item.content}/></div></div>)}
        {sending && <div className="ai-chat-message ai-chat-assistant"><div className="ai-chat-message-label">Помощник</div><div className="ai-chat-bubble ai-chat-thinking">Формирую ответ…</div></div>}
        {error && <div className="ai-chat-error" role="alert">{error}</div>}
        <div ref={endRef}/>
      </div>

      <div className="ai-chat-compose"><form className="ai-chat-form" onSubmit={send}><textarea ref={inputRef} value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send() } }} placeholder={configured ? 'Спросите о рисках или о сайте…' : 'Ожидается API-ключ'} aria-label="Вопрос помощнику" rows="2" maxLength="2000" disabled={!configured || sending}/><button type="submit" disabled={!configured || sending || !draft.trim()} aria-label="Отправить вопрос"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button></form><div className="ai-chat-footer"><span>Enter — отправить · Shift+Enter — новая строка</span><span>Только чтение AD</span></div></div>
    </section>}
    <button type="button" className="ai-chat-launcher" aria-label={open ? 'Закрыть ИИ-чат' : 'Открыть ИИ-чат'} aria-expanded={open} onClick={() => setOpen(value => !value)}>Спросить ИИ</button>
  </div>
}
