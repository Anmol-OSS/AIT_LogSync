import { NavLink, Route, Routes } from "react-router";
import { USING_MOCK_DATA } from "./api";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { PackEditor } from "./pages/PackEditor";
import { Verify } from "./pages/Verify";

const NAV = [
  { to: "/", label: "Dashboard" },
  { to: "/events", label: "Event inspector" },
  { to: "/verify", label: "Verify" },
  { to: "/packs", label: "Pack editor" },
];

export function App() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">LogSync <span>ULPF</span></div>
        <p className="tagline">Every field proves which bytes made it.</p>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}>{n.label}</NavLink>
          ))}
        </nav>
        {USING_MOCK_DATA && <div className="mock-badge" title="Screens use mock data until the backend is connected (M6)">MOCK DATA</div>}
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Events />} />
          <Route path="/events/:id" element={<Events />} />
          <Route path="/verify" element={<Verify />} />
          <Route path="/verify/:id" element={<Verify />} />
          <Route path="/packs" element={<PackEditor />} />
          <Route path="*" element={<p>Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
