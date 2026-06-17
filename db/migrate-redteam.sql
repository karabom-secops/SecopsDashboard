-- Red Team Operations tables (global — not tenant-scoped)
CREATE TABLE IF NOT EXISTS redteam_projects (
  id         SERIAL PRIMARY KEY,
  title      VARCHAR(200) NOT NULL,
  client     VARCHAR(200) NOT NULL,
  scope      TEXT NOT NULL DEFAULT '',
  status     VARCHAR(20) NOT NULL DEFAULT 'planned'
               CHECK (status IN ('planned','active','paused','completed','cancelled')),
  start_date DATE NOT NULL,
  end_date   DATE NOT NULL,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS redteam_tasks (
  id         SERIAL PRIMARY KEY,
  project_id INT NOT NULL REFERENCES redteam_projects(id) ON DELETE CASCADE,
  title      VARCHAR(300) NOT NULL,
  assignee   VARCHAR(200) NOT NULL DEFAULT '',
  due_date   DATE,
  status     VARCHAR(20) NOT NULL DEFAULT 'todo'
               CHECK (status IN ('todo','in-progress','done','blocked')),
  notes      TEXT NOT NULL DEFAULT '',
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rt_tasks_project ON redteam_tasks(project_id);
