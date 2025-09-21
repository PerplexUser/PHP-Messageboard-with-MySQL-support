<?php
/**
 * PHP Messageboard
 * ------------------------------------------------------------
 * Features:
 *  - Stores Name, Email, Website, Topic, Comment in MySQL
 *  - UTF-8/utf8mb4 everywhere (full emoji support)
 *  - Prepared statements (PDO), basic validation, CSRF, honeypot
 *  - Auto-creates the messages table if it doesn't exist
 *  - Simple pagination, nice UI, lightweight emoji picker
 *
 * HOW TO USE
 * 1) Create a MySQL database (e.g. `messageboard`).
 * 2) Put this file (messageboard.php) on your PHP 8+ web server.
 * 3) Fill in the DB credentials below in the CONFIG section.
 * 4) Visit the page. On first run it will create the table automatically.
 *
 * Security notes: This is a public demo. For production, place this behind HTTPS,
 * consider a real spam protection (e.g., reCAPTCHA), and stricter rate limits.
 */

// ------------------------------------------------------------
// CONFIG: Add your MySQL credentials here
// ------------------------------------------------------------
$DB_HOST = 'localhost';       // e.g. '127.0.0.1' or hosting address
$DB_NAME = 'messageboard';    // your database name
$DB_USER = 'root';            // your DB username
$DB_PASS = '';                // your DB password
$DB_CHARSET = 'utf8mb4';      // don't change (emoji support)
$TIMEZONE = 'Europe/Berlin';  // local time for display

// ------------------------------------------------------------
// Bootstrap
// ------------------------------------------------------------
session_start();
header('Content-Type: text/html; charset=UTF-8');
mb_internal_encoding('UTF-8');
date_default_timezone_set($TIMEZONE);

// CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Connect PDO
$dsn = "mysql:host={$DB_HOST};dbname={$DB_NAME};charset={$DB_CHARSET}";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];
try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, $options);
} catch (Throwable $e) {
    http_response_code(500);
    echo "<h1>Database connection failed</h1><p>Please check your credentials in the script.</p>";
    exit;
}

// Ensure table exists
$createSql = <<<SQL
CREATE TABLE IF NOT EXISTS messages (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NULL,
  website VARCHAR(255) NULL,
  topic VARCHAR(200) NOT NULL,
  comment TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ip VARCHAR(45) NULL,
  user_agent VARCHAR(255) NULL,
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL;
$pdo->exec($createSql);

// Helpers
function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function sanitizeUrl(?string $u): ?string {
    if (!$u) return null;
    $u = trim($u);
    if ($u === '') return null;
    // If user forgot scheme, add http://
    if (!preg_match('~^https?://~i', $u)) {
        $u = 'http://' . $u;
    }
    // Validate URL
    return filter_var($u, FILTER_VALIDATE_URL) ? $u : null;
}
function validEmail(?string $e): ?string {
    $e = trim((string)$e);
    return $e === '' ? null : (filter_var($e, FILTER_VALIDATE_EMAIL) ?: null);
}
function auto_link_and_nl2br(string $text): string {
    // Escape first
    $escaped = e($text);
    // Auto-link URLs (keeps escaping). Works fine with &amp; etc.
    $linked = preg_replace('~(https?://[^\s<]+)~iu', '<a href="$1" target="_blank" rel="noopener noreferrer nofollow">$1</a>', $escaped);
    return nl2br($linked);
}

$errors = [];
$notice = null;

// Handle POST (new message)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $hp = $_POST['nickname'] ?? ''; // honeypot field (should be empty)
    $token = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        $errors[] = 'Security check failed. Please try again.';
    }
    if ($hp !== '') {
        $errors[] = 'Spam protection triggered.';
    }

    $name = trim($_POST['name'] ?? '');
    $email = validEmail($_POST['email'] ?? null);
    $website = sanitizeUrl($_POST['website'] ?? null);
    $topic = trim($_POST['topic'] ?? '');
    $comment = trim($_POST['comment'] ?? '');

    if ($name === '' || mb_strlen($name) < 2) {
        $errors[] = 'Please enter your name (at least 2 characters).';
    }
    if ($topic === '' || mb_strlen($topic) < 2) {
        $errors[] = 'Please enter a topic (at least 2 characters).';
    }
    if ($comment === '' || mb_strlen($comment) < 2) {
        $errors[] = 'Please write a comment (at least 2 characters).';
    }
    if (!is_null($email) && mb_strlen($email) > 255) {
        $errors[] = 'Email is too long.';
    }
    if (!is_null($website) && mb_strlen($website) > 255) {
        $errors[] = 'Website URL is too long.';
    }

    if (!$errors) {
        $stmt = $pdo->prepare('INSERT INTO messages (name, email, website, topic, comment, ip, user_agent) VALUES (:name, :email, :website, :topic, :comment, :ip, :ua)');
        $stmt->bindValue(':name', $name);
        $stmt->bindValue(':email', $email);
        $stmt->bindValue(':website', $website);
        $stmt->bindValue(':topic', $topic);
        $stmt->bindValue(':comment', $comment);
        $stmt->bindValue(':ip', $_SERVER['REMOTE_ADDR'] ?? null);
        $stmt->bindValue(':ua', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 250));
        $stmt->execute();

        // Post/Redirect/Get to avoid duplicate submissions
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?') . '?posted=1');
        exit;
    }
}

if (isset($_GET['posted'])) {
    $notice = 'Your message was posted successfully! 🎉';
}

// Pagination
$perPage = 10;
$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page - 1) * $perPage;
$total = (int)$pdo->query('SELECT COUNT(*) FROM messages')->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));

$stmt = $pdo->prepare('SELECT * FROM messages ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset');
$stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$messages = $stmt->fetchAll();

// For nice date labels
function prettyDate(string $ts): string {
    $t = strtotime($ts);
    return date('M d, Y \u\m H:i', $t); // e.g. Sep 21, 2025 um 14:03
}

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Messageboard</title>
  <style>
    :root {
      --bg: #0f172a;        /* slate-900 */
      --panel: #111827;     /* gray-900 */
      --muted: #94a3b8;     /* slate-400 */
      --text: #e5e7eb;      /* gray-200 */
      --accent: #10b981;    /* emerald-500 */
      --accent-2: #22d3ee;  /* cyan-400 */
      --danger: #ef4444;    /* red-500 */
      --shadow: 0 10px 30px rgba(0,0,0,.35);
      --radius: 16px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica Neue, Arial, "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif;
      background: radial-gradient(1200px 800px at 10% -10%, rgba(34,211,238,.08), transparent 40%),
                  radial-gradient(1000px 600px at 90% 0%, rgba(16,185,129,.08), transparent 40%),
                  var(--bg);
      color: var(--text);
    }
    .container { max-width: 980px; margin: 0 auto; padding: 28px 16px 80px; }
    .hero { display: flex; align-items: center; gap: 14px; }
    .logo { font-size: 32px; }
    .title { font-size: 28px; font-weight: 800; letter-spacing: .2px; }
    .subtitle { color: var(--muted); margin-top: 4px; }

    .grid { display: grid; grid-template-columns: 1fr; gap: 24px; margin-top: 28px; }
    @media (min-width: 900px) { .grid { grid-template-columns: 1fr 1fr; } }

    .card { background: linear-gradient(180deg, rgba(255,255,255,.03), rgba(255,255,255,.02)); border: 1px solid rgba(148,163,184,.15);
            border-radius: var(--radius); box-shadow: var(--shadow); }
    .card .card-body { padding: 18px; }

    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .form-row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
    .field { display: flex; flex-direction: column; gap: 6px; }
    label { font-size: 13px; color: var(--muted); }
    input[type=text], input[type=email], textarea {
      width: 100%; padding: 12px 14px; border-radius: 14px; border: 1px solid rgba(148,163,184,.2);
      background: rgba(2,6,23,.65); color: var(--text); outline: none; transition: border .15s ease;
    }
    input:focus, textarea:focus { border-color: var(--accent-2); box-shadow: 0 0 0 3px rgba(34,211,238,.15); }
    textarea { min-height: 140px; resize: vertical; }

    .emoji-bar { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 0; }
    .emoji-btn { font-size: 20px; line-height: 1; padding: 6px 8px; border-radius: 10px; border: 1px solid rgba(148,163,184,.2); background: rgba(255,255,255,.03); cursor: pointer; }
    .emoji-btn:hover { transform: translateY(-1px); }

    .actions { display: flex; justify-content: space-between; align-items: center; margin-top: 12px; }
    .btn {
      border: 0; background: linear-gradient(180deg, var(--accent), #0ea5e9); color: white; font-weight: 700;
      padding: 12px 16px; border-radius: 14px; cursor: pointer; box-shadow: var(--shadow);
    }
    .btn:active { transform: translateY(1px); }

    .muted { color: var(--muted); font-size: 14px; }
    .errors { border-left: 3px solid var(--danger); padding: 10px 12px; background: rgba(239,68,68,.08); border-radius: 10px; }
    .notice { border-left: 3px solid var(--accent); padding: 10px 12px; background: rgba(16,185,129,.12); border-radius: 10px; }

    .message { padding: 16px; border-radius: 14px; border: 1px solid rgba(148,163,184,.15); background: rgba(2,6,23,.45); }
    .message + .message { margin-top: 12px; }
    .meta { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
    .name { font-weight: 800; }
    .topic { font-weight: 700; background: rgba(34,197,94,.18); padding: 2px 8px; border-radius: 999px; }
    .time { color: var(--muted); font-size: 12px; }
    .comment { margin-top: 8px; line-height: 1.6; }

    .paginator { display: flex; justify-content: center; gap: 8px; margin-top: 16px; }
    .page { padding: 8px 12px; border-radius: 12px; border: 1px solid rgba(148,163,184,.2); background: rgba(255,255,255,.03); text-decoration: none; color: var(--text); }
    .page.active { border-color: var(--accent-2); box-shadow: 0 0 0 3px rgba(34,211,238,.15) inset; }

    /* Honeypot field hidden */
    .hp-wrap { position: absolute; left: -9999px; top: -9999px; }
    footer { margin-top: 40px; color: var(--muted); font-size: 13px; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <div class="logo">💬</div>
      <div>
        <div class="title">Messageboard</div>
        <div class="subtitle">A modern, emoji-friendly guestbook / discussion wall.</div>
      </div>
    </div>

    <div class="grid">
      <!-- Post form -->
      <div class="card">
        <div class="card-body">
          <h2>Leave a message 📝</h2>

          <?php if ($errors): ?>
            <div class="errors">
              <strong>Oops!</strong> Please fix the following:
              <ul>
                <?php foreach ($errors as $err): ?>
                  <li><?= e($err) ?></li>
                <?php endforeach; ?>
              </ul>
            </div>
          <?php endif; ?>

          <?php if ($notice): ?>
            <div class="notice">✅ <?= e($notice) ?></div>
          <?php endif; ?>

          <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">

            <div class="form-row-3">
              <div class="field">
                <label for="name">Name *</label>
                <input id="name" name="name" type="text" maxlength="100" required placeholder="Your name" value="<?= isset($_POST['name']) ? e($_POST['name']) : '' ?>">
              </div>
              <div class="field">
                <label for="email">Email (not shown)</label>
                <input id="email" name="email" type="email" maxlength="255" placeholder="you@example.com" value="<?= isset($_POST['email']) ? e($_POST['email']) : '' ?>">
              </div>
              <div class="field">
                <label for="website">Website</label>
                <input id="website" name="website" type="text" maxlength="255" placeholder="https://your-site.com" value="<?= isset($_POST['website']) ? e($_POST['website']) : '' ?>">
              </div>
            </div>

            <div class="field" style="margin-top:12px;">
              <label for="topic">Topic *</label>
              <input id="topic" name="topic" type="text" maxlength="200" required placeholder="What is this about?">
              <div class="emoji-bar" data-target="topic">
                <!-- Add/adjust emojis as you like -->
                <?php $emojis = ['😀','😂','😍','😉','🤔','👍','🔥','🎉','🚀','🙏','😅','😎','🤖','💡','✅','❌','❤️','✨','☕️','📌','📎','🛠️','🧠'];
                foreach ($emojis as $emo): ?>
                  <button class="emoji-btn" type="button" aria-label="emoji"><?= $emo ?></button>
                <?php endforeach; ?>
              </div>
            </div>

            <div class="field" style="margin-top:12px;">
              <label for="comment">Comment *</label>
              <textarea id="comment" name="comment" maxlength="5000" required placeholder="Say something nice… Use emojis! 🎉"></textarea>
              <div class="emoji-bar" data-target="comment">
                <?php foreach ($emojis as $emo): ?>
                  <button class="emoji-btn" type="button" aria-label="emoji"><?= $emo ?></button>
                <?php endforeach; ?>
              </div>
            </div>

            <!-- Honeypot -->
            <div class="hp-wrap">
              <label for="nickname">If you are human, leave this empty</label>
              <input id="nickname" name="nickname" type="text" autocomplete="off">
            </div>

            <div class="actions">
              <div class="muted">By posting, you agree your message may be stored and shown publicly (email hidden).</div>
              <button class="btn" type="submit">Post message ✨</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Messages list -->
      <div class="card">
        <div class="card-body">
          <h2>Recent messages 🚀</h2>
          <div class="muted">Total: <?= (int)$total ?> message<?= $total === 1 ? '' : 's' ?></div>

          <div style="margin-top:12px;">
            <?php if (!$messages): ?>
              <p class="muted">No messages yet. Be the first! ✍️</p>
            <?php else: ?>
              <?php foreach ($messages as $m): ?>
                <article class="message">
                  <div class="meta">
                    <?php if (!empty($m['website'])): ?>
                      <span class="name"><a href="<?= e($m['website']) ?>" target="_blank" rel="noopener noreferrer nofollow"><?= e($m['name']) ?></a></span>
                    <?php else: ?>
                      <span class="name"><?= e($m['name']) ?></span>
                    <?php endif; ?>
                    <span class="topic"><?= e($m['topic']) ?></span>
                    <span class="time">• <?= prettyDate($m['created_at']) ?></span>
                  </div>
                  <div class="comment"><?= auto_link_and_nl2br($m['comment']) ?></div>
                </article>
              <?php endforeach; ?>
            <?php endif; ?>
          </div>

          <?php if ($totalPages > 1): ?>
            <div class="paginator">
              <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                <?php $url = strtok($_SERVER['REQUEST_URI'], '?') . '?page=' . $i; ?>
                <a class="page <?= $i === $page ? 'active' : '' ?>" href="<?= e($url) ?>"><?= $i ?></a>
              <?php endfor; ?>
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <footer>
     www.perplex.click
    </footer>
  </div>

  <script>
    // Keep track of the last focused input/textarea for emoji insertion
    let lastTarget = null;
    const topic = document.getElementById('topic');
    const comment = document.getElementById('comment');
    [topic, comment].forEach(el => {
      el.addEventListener('focus', () => { lastTarget = el; });
      el.addEventListener('click', () => { lastTarget = el; });
      el.addEventListener('keyup', () => { lastTarget = el; });
    });

    function insertAtCursor(input, text) {
      if (!input) return;
      const start = input.selectionStart ?? input.value.length;
      const end = input.selectionEnd ?? input.value.length;
      const before = input.value.substring(0, start);
      const after = input.value.substring(end);
      input.value = before + text + after;
      const pos = start + text.length;
      input.focus();
      input.setSelectionRange(pos, pos);
    }

    document.querySelectorAll('.emoji-bar').forEach(bar => {
      bar.addEventListener('click', (e) => {
        const btn = e.target.closest('.emoji-btn');
        if (!btn) return;
        // Prefer the bar's target; if missing, fallback to last focused
        const targetId = bar.getAttribute('data-target');
        const target = targetId ? document.getElementById(targetId) : lastTarget;
        insertAtCursor(target, btn.textContent);
      });
    });
  </script>
</body>
</html>
