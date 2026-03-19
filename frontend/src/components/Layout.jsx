import { useTheme } from '../theme.jsx';
import ThemeToggle from './ThemeToggle.jsx';
import { Link } from 'react-router-dom';

const Layout = ({ children }) => {
  const { theme } = useTheme();

  return (
    <div className="min-h-screen bg-base-100 text-base-content" data-theme={theme}>
      <header className="navbar bg-base-200 shadow-lg">
        <div className="flex-1">
          <Link to="/" className="btn btn-ghost text-xl">Centaur‑Jarvis</Link>
          <nav className="ml-6">
            <ul className="menu menu-horizontal px-1">
              <li><Link to="/">Dashboard</Link></li>
              <li><Link to="/reports">Reports</Link></li>
            </ul>
          </nav>
        </div>
        <div className="flex-none">
          <ThemeToggle />
        </div>
      </header>
      <main className="container mx-auto p-6">
        {children}
      </main>
      <footer className="footer footer-center p-4 bg-base-300 text-base-content">
        <aside>
          <p>Centaur‑Jarvis Web UI • {new Date().getFullYear()}</p>
        </aside>
      </footer>
    </div>
  );
};

export default Layout;