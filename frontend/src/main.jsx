import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx?brand=sidebar-clean-5'
import './styles.css?brand=infraradar-plan-modal'
import './referenceRefresh.css?rev=5'

createRoot(document.getElementById('root')).render(
  <React.StrictMode><App /></React.StrictMode>,
)
