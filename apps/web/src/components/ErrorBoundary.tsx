import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in component:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-[#090d16] text-white p-6">
          <div className="max-w-md w-full p-6 bg-slate-900 border border-slate-800 rounded-xl">
            <h2 className="text-xl font-bold text-red-400 mb-2">System Error Encountered</h2>
            <p className="text-slate-400 text-sm mb-4">
              An unexpected error occurred within the AgentShield UI container.
            </p>
            <pre className="text-xs bg-slate-950 p-3 rounded text-red-300 overflow-x-auto">
              {this.state.error?.message || 'Unknown error'}
            </pre>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm transition-colors"
            >
              Reset Application State
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
