import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx?brand=infraradar-plan-modal'
import './styles.css?brand=infraradar-plan-modal'

createRoot(document.getElementById('root')).render(
  <React.StrictMode><App /></React.StrictMode>,
)
