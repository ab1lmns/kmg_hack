import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

export default function SourcePicker({ value, onChange, ldapReady, scanning, onOpenSettings }) {
  const [open, setOpen] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const pickerRef = useRef(null)
  const triggerRef = useRef(null)
  const closeRef = useRef(null)
  const guideRef = useRef(null)

  useEffect(() => {
    if (!open) return
    const outside = event => { if (!pickerRef.current?.contains(event.target)) setOpen(false) }
    const escape = event => { if (event.key === 'Escape') { setOpen(false); triggerRef.current?.focus() } }
    document.addEventListener('pointerdown', outside)
    document.addEventListener('keydown', escape)
    return () => { document.removeEventListener('pointerdown', outside); document.removeEventListener('keydown', escape) }
  }, [open])

  useEffect(() => {
    if (!showGuide) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    closeRef.current?.focus()
    const modalKeys = event => {
      if (event.key === 'Escape') setShowGuide(false)
      if (event.key !== 'Tab') return
      const focusable = [...guideRef.current.querySelectorAll('button:not(:disabled)')]
      if (event.shiftKey && document.activeElement === focusable[0]) {
        event.preventDefault(); focusable.at(-1).focus()
      } else if (!event.shiftKey && document.activeElement === focusable.at(-1)) {
        event.preventDefault(); focusable[0].focus()
      }
    }
    document.addEventListener('keydown', modalKeys)
    return () => {
      document.body.style.overflow = previousOverflow
      document.removeEventListener('keydown', modalKeys)
      triggerRef.current?.focus()
    }
  }, [showGuide])

  const select = next => { onChange(next); setOpen(false); triggerRef.current?.focus() }
  const settings = () => { setOpen(false); setShowGuide(false); onOpenSettings() }

  return <>
    <div className="source-picker" ref={pickerRef}>
      <button ref={triggerRef} className="source-picker-trigger" type="button" aria-label={`Данные для следующего анализа: ${value === 'ldap' ? 'Active Directory' : 'Демо'}. Выбрать источник`} aria-expanded={open} aria-controls="source-picker-list" disabled={scanning} onClick={() => setOpen(current => !current)}>
        Данные: {value === 'ldap' ? 'AD' : 'Демо'} <span className="source-picker-chevron" aria-hidden="true"/>
      </button>
      {open && <div id="source-picker-list" className="source-picker-list" aria-label="Выбор источника анализа">
        <div className="source-picker-heading">Данные для анализа</div>
        <button className="source-picker-option" type="button" disabled={!ldapReady} aria-pressed={value === 'ldap'} onClick={() => select('ldap')}>
          <span><strong>Active Directory</strong><small>{ldapReady ? 'Живые данные каталога' : 'Требуется настройка подключения'}</small></span>
          {value === 'ldap' && <span className="source-picker-selected">Выбран</span>}
        </button>
        <button className="source-picker-option" type="button" aria-pressed={value === 'demo'} onClick={() => select('demo')}>
          <span><strong>Демо</strong><small>Пример данных для просмотра интерфейса</small></span>
          {value === 'demo' && <span className="source-picker-selected">Выбран</span>}
        </button>
        <button className="source-picker-add" type="button" onClick={() => { setOpen(false); setShowGuide(true) }}>+ Добавить источник</button>
      </div>}
    </div>
    {showGuide && createPortal(<div className="source-guide-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setShowGuide(false) }}>
      <section ref={guideRef} className="source-guide" role="dialog" aria-modal="true" aria-labelledby="source-guide-title">
        <div className="source-guide-head"><span>Источники данных</span><button ref={closeRef} type="button" onClick={() => setShowGuide(false)} aria-label="Закрыть">×</button></div>
        <h2 id="source-guide-title">Добавить источник</h2>
        <p>Новый каталог подключает администратор стенда. После настройки он станет доступен для проверки и анализа.</p>
        <div className="source-guide-steps">
          <div><b>01</b><span><strong>Подготовить доступ</strong><small>Учётная запись с правами чтения и защищённый канал до каталога.</small></span></div>
          <div><b>02</b><span><strong>Проверить соединение</strong><small>Статус и сведения о текущем подключении находятся в разделе «Подключение».</small></span></div>
        </div>
        <div className="source-guide-actions"><button type="button" className="source-guide-secondary" onClick={() => setShowGuide(false)}>Закрыть</button><button type="button" className="primary-button" onClick={settings}>Открыть подключение</button></div>
      </section>
    </div>, document.body)}
  </>
}
