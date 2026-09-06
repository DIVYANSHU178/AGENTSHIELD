import { ErrorBoundary } from './components/ErrorBoundary';
import { AuthProvider } from './context/AuthContext';
import { MotionProvider } from './context/MotionContext';
import { Home } from './pages/Home';

export function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <MotionProvider>
          <Home />
        </MotionProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
