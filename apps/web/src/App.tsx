import { ErrorBoundary } from './components/ErrorBoundary';
import { Home } from './pages/Home';

export function App() {
  return (
    <ErrorBoundary>
      <Home />
    </ErrorBoundary>
  );
}

export default App;
