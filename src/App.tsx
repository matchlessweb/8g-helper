import { useEffect } from 'react'
import './App.css'
import { AppShell } from './app/AppShell'
import { Analyzer } from './components/Analyzer'
import { Faq, HowItWorks, RuleGroups } from './components/Sections'
import { ThemeProvider } from './theme/ThemeProvider'

function App() {
  // Marks the page interactive once React has attached to the prerendered markup; the e2e tests wait for it.
  useEffect(() => {
    document.documentElement.dataset.ready = 'true'
  }, [])

  return (
    <ThemeProvider>
      <AppShell>
        <Analyzer />
        <HowItWorks />
        <RuleGroups />
        <Faq />
      </AppShell>
    </ThemeProvider>
  )
}

export default App
