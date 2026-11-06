"""
CloudPool Desktop - GUI Application
Multi-Cloud Storage Aggregator with AES-256-GCM Encryption,
RAID-5 Erasure Coding, True Remote Deletion, and Metadata Mirroring.
"""

import os
import sys
import time
import gc
import queue
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime

# Ensure project root is in sys.path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from network_engine import NetworkEngine, CHUNK_SIZE
from core_engine import (
    APP_DIR,
    VAULT_DIR,
    DEFAULT_META_PASSPHRASE,
    MetadataEngine,
    ProcessManager,
    RCLONE_BIN,
    format_bytes
)

# Import TkinterDnD2 for drag-and-drop support
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False
    print("Warning: tkinterdnd2 not available. Drag-and-drop disabled; file picker available.")

# UI Palette (Modern Dark Theme)
BG_DARK = "#12131c"
BG_CARD = "#1c1d2d"
BG_CARD_LIGHT = "#24263a"
BG_INPUT = "#171826"
ACCENT_PRIMARY = "#6366f1"   # Indigo
ACCENT_HOVER = "#4f46e5"
ACCENT_SUCCESS = "#10b981"   # Emerald
ACCENT_WARNING = "#f59e0b"   # Amber
ACCENT_DANGER = "#ef4444"    # Rose/Red
ACCENT_CYAN = "#06b6d4"      # Cyan
TEXT_WHITE = "#f8fafc"
TEXT_MUTED = "#94a3b8"
TEXT_DIM = "#64748b"
BORDER_COLOR = "#2e324a"


def format_bytes(num_bytes):
    """Converts bytes into human-readable string (B, KB, MB, GB, TB)."""
    if num_bytes is None:
        return "0 B"
    num_bytes = float(num_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}" if unit in ['MB', 'GB', 'TB'] else f"{int(num_bytes)} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


class CloudPoolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CloudPool Desktop — Multi-Cloud Storage Aggregator")
        self.root.geometry("1060x800")
        self.root.minsize(940, 700)
        self.root.configure(bg=BG_DARK)

        # Initialize Real Network & Database Engines
        self.net_engine = NetworkEngine()
        self.db = self.net_engine.db

        # Thread-safe Communication Queue
        self.msg_queue = queue.Queue()
        self.is_busy = False

        # State Variables
        self.selected_tier = tk.StringVar(value="STABLE")
        self.enable_parity_var = tk.BooleanVar(value=True)  # RAID-5 Parity enabled by default
        self.status_var = tk.StringVar(value="Ready. Drop files to encrypt & pool.")
        self.progress_val = tk.DoubleVar(value=0.0)
        self.progress_detail = tk.StringVar(value="0.0% • Idle")
        self.chunk_progress_val = tk.DoubleVar(value=0.0)
        self.chunk_progress_detail = tk.StringVar(value="Active Chunk: Idle")
        self.file_progress_var = tk.StringVar(value="Files: 0/0 (0 remaining) • 0 B / 0 B (0 B remaining)")
        self.speed_eta_var = tk.StringVar(value="⚡ Speed: -- • ⏳ ETA: --")
        self.pool_summary_var = tk.StringVar(value="Loading pool statistics...")

        # Storage Pool Health & Unified Quota Bar
        self.pool_quota_val = tk.DoubleVar(value=0.0)
        self.pool_quota_text = tk.StringVar(value="Unified Storage Pool: Initializing...")

        # In-line Retry State
        self.last_failed_upload = None

        # Pre-Flight Remote Status Prober Map
        self.remote_health_map = {}

        # Column Sorting State for VFS Treeview
        self.sort_state = {}
        self.column_titles = {
            "name": "Virtual Item Name",
            "type": "Type",
            "size": "Total Size",
            "chunks": "Chunks",
            "parity": "RAID-5 Parity",
            "uploaded_at": "Uploaded At",
            "item_id": "Virtual ID"
        }

        # VFS Hierarchical State Variables
        self.current_folder_id = None
        self.search_query_var = tk.StringVar(value="")
        self.path_display_var = tk.StringVar(value="📁 Location: / (Root)")
        self.target_folder_var = tk.StringVar(value="📁 / (Root)")
        self.folder_id_map = {"📁 / (Root)": None}
        self.folder_display_list = ["📁 / (Root)"]

        # Setup Styles & UI Components
        self._configure_styles()
        self._build_header()
        self._build_tabs()
        self._build_bottom_status()

        # Handle clean window close with silent metadata mirroring
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)

        # Start periodic queue polling (60 FPS responsiveness)
        self.root.after(35, self._process_queue)

        # Initial data load & sync (with automatic ghost remote cleanup)
        pruned = self.db.prune_ghost_remotes()
        if pruned:
            self.log(f"[STARTUP SANITIZER] Pruned {len(pruned)} accidental / ghost remote(s): {', '.join(pruned)}")
        self.refresh_all_data()

        # Launch silent pre-flight background ping to all 9 remotes
        threading.Thread(target=self._run_preflight_ping, daemon=True).start()

    def _configure_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Global ttk styles
        style.configure(".", background=BG_DARK, foreground=TEXT_WHITE, font=("Segoe UI", 9))

        # Notebook (Tabs)
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", 
                        background=BG_CARD, 
                        foreground=TEXT_MUTED, 
                        padding=[18, 9], 
                        font=("Segoe UI", 10, "bold"),
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT_PRIMARY), ("active", BG_CARD_LIGHT)],
                  foreground=[("selected", TEXT_WHITE), ("active", TEXT_WHITE)])

        # Treeview (Tables)
        style.configure("Treeview",
                        background=BG_INPUT,
                        foreground=TEXT_WHITE,
                        fieldbackground=BG_INPUT,
                        rowheight=28,
                        font=("Segoe UI", 9),
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background=BG_CARD_LIGHT,
                        foreground=TEXT_WHITE,
                        font=("Segoe UI", 9, "bold"),
                        padding=[8, 6],
                        borderwidth=0)
        style.map("Treeview", 
                  background=[("selected", ACCENT_PRIMARY)],
                  foreground=[("selected", TEXT_WHITE)])

        # Overall Batch Progressbar
        style.configure("Cloud.Horizontal.TProgressbar",
                        troughcolor=BG_INPUT,
                        background=ACCENT_PRIMARY,
                        thickness=14,
                        borderwidth=0)

        # Chunk-level Sub-Progressbar (Emerald Green)
        style.configure("Chunk.Horizontal.TProgressbar",
                        troughcolor=BG_INPUT,
                        background=ACCENT_SUCCESS,
                        thickness=8,
                        borderwidth=0)

        # Unified Storage Pool Quota Bar (Cyan)
        style.configure("Quota.Horizontal.TProgressbar",
                        troughcolor=BG_INPUT,
                        background=ACCENT_CYAN,
                        thickness=10,
                        borderwidth=0)

        # Combobox styling (High-contrast fix: eliminates white-on-white text)
        style.configure("TCombobox",
                        fieldbackground=BG_INPUT,
                        background=BG_CARD_LIGHT,
                        foreground=TEXT_WHITE,
                        arrowcolor=TEXT_WHITE,
                        darkcolor=BORDER_COLOR,
                        lightcolor=BORDER_COLOR,
                        bordercolor=BORDER_COLOR,
                        padding=[6, 4])
        style.map("TCombobox",
                  fieldbackground=[
                      ("readonly", BG_INPUT),
                      ("active", BG_INPUT),
                      ("focus", BG_INPUT),
                      ("!disabled", BG_INPUT)
                  ],
                  foreground=[
                      ("readonly", TEXT_WHITE),
                      ("active", TEXT_WHITE),
                      ("focus", TEXT_WHITE),
                      ("!disabled", TEXT_WHITE)
                  ],
                  arrowcolor=[("active", ACCENT_PRIMARY), ("!disabled", TEXT_WHITE)])

        # Entry styling
        style.configure("TEntry",
                        fieldbackground=BG_INPUT,
                        foreground=TEXT_WHITE,
                        insertcolor=TEXT_WHITE,
                        borderwidth=1,
                        relief="solid")
        style.map("TEntry",
                  fieldbackground=[("active", BG_INPUT), ("focus", BG_INPUT)],
                  foreground=[("active", TEXT_WHITE), ("focus", TEXT_WHITE)])

        # Tk Option Database styling (ensures popdown listboxes and popup dialogs are dark & high-contrast)
        self.root.option_add("*TCombobox*Listbox.background", BG_CARD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT_WHITE)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_PRIMARY)
        self.root.option_add("*TCombobox*Listbox.selectForeground", TEXT_WHITE)
        self.root.option_add("*TCombobox*Listbox.font", ("Segoe UI", 9))
        self.root.option_add("*Entry.background", BG_INPUT)
        self.root.option_add("*Entry.foreground", TEXT_WHITE)
        self.root.option_add("*Entry.insertBackground", TEXT_WHITE)
        self.root.option_add("*Entry.selectBackground", ACCENT_PRIMARY)
        self.root.option_add("*Entry.selectForeground", TEXT_WHITE)

    def _build_header(self):
        """Top banner with app branding, live metrics, Unified Quota Bar, and metadata backup status."""
        header_frame = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=10, highlightthickness=1, highlightbackground=BORDER_COLOR)
        header_frame.pack(fill=tk.X, side=tk.TOP)

        top_row = tk.Frame(header_frame, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        # Title & Badges
        left_box = tk.Frame(top_row, bg=BG_CARD)
        left_box.pack(side=tk.LEFT, fill=tk.Y)

        title_lbl = tk.Label(left_box, text="⚡ CloudPool Desktop", font=("Segoe UI", 15, "bold"), fg=TEXT_WHITE, bg=BG_CARD)
        title_lbl.pack(anchor="w")

        subtitle_lbl = tk.Label(
            left_box, 
            text="AES-256-GCM Zero-Knowledge Sharding • 20 MB In-Memory Chunks • RAID-5 Parity • Automated Mirroring", 
            font=("Segoe UI", 8), 
            fg=TEXT_MUTED, 
            bg=BG_CARD
        )
        subtitle_lbl.pack(anchor="w", pady=(1, 0))

        # Right Summary Badges & Quick Action
        right_box = tk.Frame(top_row, bg=BG_CARD)
        right_box.pack(side=tk.RIGHT, fill=tk.Y)

        self.summary_lbl = tk.Label(
            right_box, 
            textvariable=self.pool_summary_var, 
            font=("Segoe UI", 9, "bold"), 
            fg=ACCENT_CYAN, 
            bg=BG_CARD,
            justify="right"
        )
        self.summary_lbl.pack(anchor="e")

        status_row = tk.Frame(right_box, bg=BG_CARD)
        status_row.pack(anchor="e", pady=(2, 0))

        key_status_lbl = tk.Label(
            status_row, 
            text="🔒 AES Master Key: Active  |  🛡️ RAID-5: Enabled  |  ", 
            font=("Segoe UI", 8), 
            fg=ACCENT_SUCCESS, 
            bg=BG_CARD
        )
        key_status_lbl.pack(side=tk.LEFT)

        meta_sync_btn = tk.Button(
            status_row,
            text="☁ Mirror Metadata",
            font=("Segoe UI", 8, "bold"),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=6,
            pady=1,
            cursor="hand2",
            command=self._on_manual_metadata_sync
        )
        meta_sync_btn.pack(side=tk.LEFT)

        # Massive Unified Storage Pool Quota Bar (Storage Health Dashboard)
        quota_frame = tk.Frame(header_frame, bg=BG_CARD)
        quota_frame.pack(fill=tk.X, pady=(8, 2))

        quota_lbl_row = tk.Frame(quota_frame, bg=BG_CARD)
        quota_lbl_row.pack(fill=tk.X, pady=(0, 2))

        self.quota_title_lbl = tk.Label(
            quota_lbl_row,
            textvariable=self.pool_quota_text,
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD
        )
        self.quota_title_lbl.pack(side=tk.LEFT)

        self.quota_pct_lbl = tk.Label(
            quota_lbl_row,
            text="0.0% Used",
            font=("Segoe UI", 8, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_CARD
        )
        self.quota_pct_lbl.pack(side=tk.RIGHT)

        self.pool_quota_bar = ttk.Progressbar(
            quota_frame,
            variable=self.pool_quota_val,
            maximum=100.0,
            style="Quota.Horizontal.TProgressbar"
        )
        self.pool_quota_bar.pack(fill=tk.X)

    def _build_tabs(self):
        """Builds the 3 main views: Upload/Ingest, Virtual Vault, and Cloud Accounts."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)

        self.tab_upload = tk.Frame(self.notebook, bg=BG_DARK, padx=12, pady=12)
        self.tab_files = tk.Frame(self.notebook, bg=BG_DARK, padx=12, pady=12)
        self.tab_accounts = tk.Frame(self.notebook, bg=BG_DARK, padx=12, pady=12)

        self.notebook.add(self.tab_upload, text="  ⬆  Upload & Shard  ")
        self.notebook.add(self.tab_files, text="  📁  Virtual Files Vault  ")
        self.notebook.add(self.tab_accounts, text="  ☁  Cloud Storage Pool  ")

        self._build_upload_tab()
        self._build_files_tab()
        self._build_accounts_tab()

    # -------------------------------------------------------------
    # TAB 1: UPLOAD & SHARD (Drag-and-Drop, Tiering, RAID-5, Progress)
    # -------------------------------------------------------------
    def _build_upload_tab(self):
        # Options Card: Tier Selection + RAID-5 Parity Toggle
        opts_card = tk.LabelFrame(
            self.tab_upload, 
            text=" Storage Routing & Resiliency Settings ", 
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_WHITE, 
            bg=BG_CARD, 
            padx=14, 
            pady=8,
            bd=1,
            relief="solid",
            highlightthickness=0
        )
        opts_card.pack(fill=tk.X, side=tk.TOP, pady=(0, 10))

        routing_row = tk.Frame(opts_card, bg=BG_CARD)
        routing_row.pack(fill=tk.X, pady=(2, 4))

        routing_badge = tk.Label(
            routing_row,
            text="🛡️ Automatic Storage Routing: STABLE High-Durability Cloud Pool Active",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT_SUCCESS,
            bg=BG_CARD
        )
        routing_badge.pack(side=tk.LEFT)

        routing_desc = tk.Label(
            routing_row,
            text=" • Transfers automatically shard and route to reliable cloud remotes (OneDrive, Google Drive, MEGA).",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD
        )
        routing_desc.pack(side=tk.LEFT)

        # RAID-5 Checkbox
        parity_chk = tk.Checkbutton(
            opts_card,
            text="🛡️ Generate RAID-5 XOR Parity Chunk (Protects file against single-account outage, suspension, or deletion)",
            variable=self.enable_parity_var,
            font=("Segoe UI", 8, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_CARD,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            selectcolor=BG_INPUT,
            cursor="hand2"
        )
        parity_chk.pack(anchor="w", pady=(4, 4))

        # Target Virtual Folder Selector
        dest_row = tk.Frame(opts_card, bg=BG_CARD)
        dest_row.pack(fill=tk.X, pady=(2, 2))

        tk.Label(
            dest_row, 
            text="📁 Destination Folder:", 
            font=("Segoe UI", 8, "bold"), 
            fg=TEXT_WHITE, 
            bg=BG_CARD
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.target_folder_combo = ttk.Combobox(
            dest_row, 
            textvariable=self.target_folder_var,
            values=self.folder_display_list, 
            state="readonly", 
            width=36
        )
        self.target_folder_combo.set("📁 / (Root)")
        self.target_folder_combo.pack(side=tk.LEFT, padx=(0, 8))

        new_folder_quick_btn = tk.Button(
            dest_row,
            text="➕ New Folder",
            font=("Segoe UI", 8, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_CYAN,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=8,
            pady=1,
            cursor="hand2",
            command=self._prompt_new_folder
        )
        new_folder_quick_btn.pack(side=tk.LEFT)

        # Drag & Drop Zone Card
        self.drop_frame = tk.Frame(
            self.tab_upload,
            bg=BG_CARD,
            padx=20,
            pady=20,
            relief="solid",
            bd=2,
            highlightbackground=BORDER_COLOR
        )
        self.drop_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        if HAS_DND:
            try:
                self.drop_frame.drop_target_register(DND_FILES)
                self.drop_frame.dnd_bind("<<Drop>>", self._on_files_dropped)
                self.drop_frame.dnd_bind("<<DropEnter>>", self._on_drag_enter)
                self.drop_frame.dnd_bind("<<DropLeave>>", self._on_drag_leave)
            except Exception as e:
                print(f"[DND WARNING] Drag-and-drop registration bypassed: {e}")

        self.drop_icon = tk.Label(self.drop_frame, text="☁ ⬇", font=("Segoe UI", 32), fg=ACCENT_PRIMARY, bg=BG_CARD)
        self.drop_icon.pack(pady=(6, 2))

        self.drop_prompt = tk.Label(
            self.drop_frame,
            text="Drag and Drop Files or Folders Here",
            font=("Segoe UI", 13, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD
        )
        self.drop_prompt.pack(pady=2)

        self.drop_subtext = tk.Label(
            self.drop_frame,
            text="Files and folders are zero-knowledge encrypted (AES-256-GCM), RAID-5 protected, and mapped into your Virtual File System.",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD
        )
        self.drop_subtext.pack(pady=4)

        browse_row = tk.Frame(self.drop_frame, bg=BG_CARD)
        browse_row.pack(pady=6)

        browse_btn = tk.Button(
            browse_row,
            text="📄 Browse Files",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_PRIMARY,
            fg=TEXT_WHITE,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self._browse_and_upload
        )
        browse_btn.pack(side=tk.LEFT, padx=5)

        browse_folder_btn = tk.Button(
            browse_row,
            text="📁 Browse Local Folder to Pool",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_CYAN,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self._browse_folder_and_upload
        )
        browse_folder_btn.pack(side=tk.LEFT, padx=5)

        # Progress & Live Status Card
        progress_card = tk.LabelFrame(
            self.tab_upload,
            text=" Live Transfer Performance & Sharding Tracker ",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD,
            padx=14,
            pady=10,
            bd=1,
            relief="solid",
            highlightthickness=0
        )
        progress_card.pack(fill=tk.X, side=tk.BOTTOM)

        prog_head = tk.Frame(progress_card, bg=BG_CARD)
        prog_head.pack(fill=tk.X, pady=(0, 4))

        self.status_detail_lbl = tk.Label(
            prog_head,
            textvariable=self.status_var,
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_CARD,
            anchor="w"
        )
        self.status_detail_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.percent_lbl = tk.Label(
            prog_head,
            textvariable=self.progress_detail,
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD,
            anchor="e"
        )
        self.percent_lbl.pack(side=tk.RIGHT)

        # Cancel Button (Hidden by default, packed when transfer is active)
        self.cancel_btn = tk.Button(
            prog_head,
            text="⏹ Cancel Transfer",
            font=("Segoe UI", 8, "bold"),
            bg="#dc2626",
            fg=TEXT_WHITE,
            activebackground="#b91c1c",
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=10,
            pady=2,
            cursor="hand2",
            command=self._on_cancel_transfer
        )

        self.prog_bar = ttk.Progressbar(
            progress_card,
            variable=self.progress_val,
            maximum=100.0,
            style="Cloud.Horizontal.TProgressbar"
        )
        self.prog_bar.pack(fill=tk.X, pady=(2, 4))

        # Bar 2: Active Chunk Stream Sub-Bar (Per-Chunk Real-time Stream)
        chunk_head = tk.Frame(progress_card, bg=BG_CARD)
        chunk_head.pack(fill=tk.X, pady=(1, 2))

        self.chunk_status_lbl = tk.Label(
            chunk_head,
            textvariable=self.chunk_progress_detail,
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            anchor="w"
        )
        self.chunk_status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.chunk_bar = ttk.Progressbar(
            progress_card,
            variable=self.chunk_progress_val,
            maximum=100.0,
            style="Chunk.Horizontal.TProgressbar"
        )
        self.chunk_bar.pack(fill=tk.X, pady=(0, 6))

        # Metrics Row: Explicit file count / size vs remaining AND real-time speed + ETA + In-line Retry Button
        metrics_row = tk.Frame(progress_card, bg=BG_CARD)
        metrics_row.pack(fill=tk.X, pady=(0, 6))

        self.file_progress_lbl = tk.Label(
            metrics_row,
            textvariable=self.file_progress_var,
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD,
            anchor="w"
        )
        self.file_progress_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # In-line Retry Button (Dynamically packed when transfer encounters an error)
        self.retry_btn = tk.Button(
            metrics_row,
            text="🔄 Retry Failed Transfer",
            font=("Segoe UI", 8, "bold"),
            bg=ACCENT_PRIMARY,
            fg=TEXT_WHITE,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=10,
            pady=1,
            cursor="hand2",
            command=self._retry_last_failed_upload
        )
        # Hidden by default

        self.speed_eta_lbl = tk.Label(
            metrics_row,
            textvariable=self.speed_eta_var,
            font=("Segoe UI", 8, "bold"),
            fg=ACCENT_SUCCESS,
            bg=BG_CARD,
            anchor="e"
        )
        self.speed_eta_lbl.pack(side=tk.RIGHT)

        # Real-time event log
        self.log_box = tk.Text(
            progress_card,
            height=4,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            font=("Consolas", 8),
            relief="flat",
            bd=0,
            padx=8,
            pady=4
        )
        self.log_box.pack(fill=tk.X)
        self.log_box.config(state=tk.DISABLED)

    # -------------------------------------------------------------
    # TAB 2: VIRTUAL FILES VAULT (VFS Explorer, Breadcrumbs, Search)
    # -------------------------------------------------------------
    def _build_files_tab(self):
        # 1. Navigation, Breadcrumbs & Search Toolbar
        nav_bar = tk.Frame(self.tab_files, bg=BG_DARK)
        nav_bar.pack(fill=tk.X, side=tk.TOP, pady=(0, 6))

        root_btn = tk.Button(
            nav_bar,
            text="🏠 Root",
            font=("Segoe UI", 8, "bold"),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=8,
            pady=3,
            cursor="hand2",
            command=self._nav_to_root
        )
        root_btn.pack(side=tk.LEFT, padx=(0, 4))

        up_btn = tk.Button(
            nav_bar,
            text="⬆ Up",
            font=("Segoe UI", 8, "bold"),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=8,
            pady=3,
            cursor="hand2",
            command=self._nav_up_level
        )
        up_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Dynamic Clickable Breadcrumbs Path (Vault > Folder > Subfolder)
        self.breadcrumbs_frame = tk.Frame(nav_bar, bg=BG_DARK)
        self.breadcrumbs_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Search Controls (Right side of Navigation Toolbar)
        search_box = tk.Frame(nav_bar, bg=BG_DARK)
        search_box.pack(side=tk.RIGHT)

        tk.Label(
            search_box,
            text="🔍 Search:",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_DARK
        ).pack(side=tk.LEFT, padx=(0, 4))

        self.search_entry = tk.Entry(
            search_box,
            textvariable=self.search_query_var,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
            relief="flat",
            width=22
        )
        self.search_entry.pack(side=tk.LEFT, padx=(0, 4), ipady=2)
        self.search_entry.bind("<KeyRelease>", self._on_search_query_changed)
        self.search_entry.bind("<Return>", self._on_search_query_changed)

        clear_search_btn = tk.Button(
            search_box,
            text="✕ Clear",
            font=("Segoe UI", 8),
            bg=BG_CARD_LIGHT,
            fg=TEXT_MUTED,
            activebackground=BG_CARD,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=6,
            pady=1,
            cursor="hand2",
            command=self._clear_search
        )
        clear_search_btn.pack(side=tk.LEFT)

        # 2. Main File Operations Action Bar
        op_bar = tk.Frame(self.tab_files, bg=BG_DARK)
        op_bar.pack(fill=tk.X, side=tk.TOP, pady=(0, 8))

        new_folder_btn = tk.Button(
            op_bar,
            text="➕ New Folder",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_CYAN,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._prompt_new_folder
        )
        new_folder_btn.pack(side=tk.LEFT, padx=(0, 6))

        dl_btn = tk.Button(
            op_bar,
            text="📥 Download & Restore",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_PRIMARY,
            fg=TEXT_WHITE,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._on_download_selected
        )
        dl_btn.pack(side=tk.LEFT, padx=(0, 6))

        move_btn = tk.Button(
            op_bar,
            text="📦 Move...",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._prompt_move
        )
        move_btn.pack(side=tk.LEFT, padx=(0, 6))

        rename_btn = tk.Button(
            op_bar,
            text="✏️ Rename",
            font=("Segoe UI", 9),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._prompt_rename
        )
        rename_btn.pack(side=tk.LEFT, padx=(0, 6))

        del_btn = tk.Button(
            op_bar,
            text="🗑️ True Wipe from Cloud",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_DANGER,
            activebackground=BG_CARD,
            activeforeground=ACCENT_DANGER,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._on_delete_selected
        )
        del_btn.pack(side=tk.LEFT, padx=(0, 6))

        refresh_btn = tk.Button(
            op_bar,
            text="🔄 Refresh",
            font=("Segoe UI", 9),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self.refresh_all_data
        )
        refresh_btn.pack(side=tk.LEFT)

        # 3. Dual-Pane VFS Explorer (Left: Folder Hierarchy Tree, Right: Folder Contents Table)
        paned = tk.PanedWindow(self.tab_files, orient=tk.HORIZONTAL, bg=BORDER_COLOR, bd=1, sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left Pane: Hierarchical Folder Tree
        left_folder_frame = tk.Frame(paned, bg=BG_CARD, width=240)
        left_folder_frame.pack_propagate(False)

        tree_header = tk.Frame(left_folder_frame, bg=BG_CARD_LIGHT, padx=8, pady=5)
        tree_header.pack(fill=tk.X)
        tk.Label(
            tree_header,
            text="📁 Directory Structure",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD_LIGHT
        ).pack(side=tk.LEFT)

        folder_tree_box = tk.Frame(left_folder_frame, bg=BG_INPUT)
        folder_tree_box.pack(fill=tk.BOTH, expand=True)

        self.folder_tree = ttk.Treeview(folder_tree_box, selectmode="browse", show="tree")
        f_scroll = ttk.Scrollbar(folder_tree_box, orient="vertical", command=self.folder_tree.yview)
        self.folder_tree.configure(yscrollcommand=f_scroll.set)

        self.folder_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        f_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.folder_tree.bind("<<TreeviewSelect>>", self._on_folder_tree_selected)

        # Left bottom buttons
        left_btn_bar = tk.Frame(left_folder_frame, bg=BG_CARD, padx=4, pady=4)
        left_btn_bar.pack(fill=tk.X)
        tk.Button(
            left_btn_bar,
            text="➕ Subfolder",
            font=("Segoe UI", 8),
            bg=BG_CARD_LIGHT,
            fg=TEXT_WHITE,
            relief="flat",
            padx=6,
            pady=2,
            cursor="hand2",
            command=self._prompt_new_folder
        ).pack(side=tk.LEFT, padx=2)
        tk.Button(
            left_btn_bar,
            text="🗑️ Delete",
            font=("Segoe UI", 8),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_DANGER,
            relief="flat",
            padx=6,
            pady=2,
            cursor="hand2",
            command=self._on_delete_selected
        ).pack(side=tk.LEFT, padx=2)

        paned.add(left_folder_frame, minsize=180)

        # Right Pane: Directory Contents Table
        right_contents_frame = tk.Frame(paned, bg=BG_CARD)

        columns = ("name", "type", "size", "chunks", "parity", "uploaded_at", "item_id")
        self.files_tree = ttk.Treeview(right_contents_frame, columns=columns, show="headings", selectmode="browse")

        for col_id, title in self.column_titles.items():
            self.files_tree.heading(col_id, text=title, command=lambda c=col_id: self._sort_column(c))

        self.files_tree.column("name", width=250, anchor="w")
        self.files_tree.column("type", width=90, anchor="center")
        self.files_tree.column("size", width=100, anchor="center")
        self.files_tree.column("chunks", width=110, anchor="center")
        self.files_tree.column("parity", width=120, anchor="center")
        self.files_tree.column("uploaded_at", width=150, anchor="center")
        self.files_tree.column("item_id", width=210, anchor="w")

        scrollbar = ttk.Scrollbar(right_contents_frame, orient="vertical", command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=scrollbar.set)

        self.files_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.files_tree.bind("<Double-1>", self._on_table_double_click)
        self.files_tree.bind("<Button-3>", self._show_context_menu)

        paned.add(right_contents_frame, minsize=400)

        # Context Menu for Right-Click
        self._build_context_menu()

    # -------------------------------------------------------------
    # TAB 3: CLOUD STORAGE POOL (Accounts, Buffer Rule, Register, DR)
    # -------------------------------------------------------------
    def _build_accounts_tab(self):
        # Action Toolbar (Auto-sync with rclone.conf + Remove + Connectivity + Disaster Recovery)
        acc_bar = tk.Frame(self.tab_accounts, bg=BG_DARK)
        acc_bar.pack(fill=tk.X, side=tk.TOP, pady=(0, 8))

        sync_btn = tk.Button(
            acc_bar,
            text="🔄 Auto-Sync from Rclone Config",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_PRIMARY,
            fg=TEXT_WHITE,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._on_sync_rclone
        )
        sync_btn.pack(side=tk.LEFT, padx=(0, 6))

        del_remote_btn = tk.Button(
            acc_bar,
            text="🗑️ Remove / Unregister Remote",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_DANGER,
            activebackground=BG_CARD,
            activeforeground=ACCENT_DANGER,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._on_unregister_account
        )
        del_remote_btn.pack(side=tk.LEFT, padx=(0, 6))

        reconnect_btn = tk.Button(
            acc_bar,
            text="🔌 Reconnect Remote",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_CYAN,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._on_reconnect_account
        )
        reconnect_btn.pack(side=tk.LEFT, padx=(0, 6))

        test_btn = tk.Button(
            acc_bar,
            text="🩺 Test Remotes Connectivity",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_SUCCESS,
            activebackground=BG_CARD,
            activeforeground=ACCENT_SUCCESS,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._on_test_connectivity
        )
        test_btn.pack(side=tk.LEFT, padx=(0, 6))

        dr_btn = tk.Button(
            acc_bar,
            text="📥 Disaster Recovery: Restore DB from Cloud",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=ACCENT_CYAN,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._on_disaster_recovery
        )
        dr_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Accounts Table
        table_frame = tk.Frame(self.tab_accounts, bg=BG_CARD, bd=1, relief="solid")
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        columns = ("priority", "account_name", "provider", "tier", "usable_cap", "used", "free", "status")
        self.accounts_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.accounts_tree.heading("priority", text="Priority Tier")
        self.accounts_tree.heading("account_name", text="Remote Name (Rclone)")
        self.accounts_tree.heading("provider", text="Cloud Provider")
        self.accounts_tree.heading("tier", text="Tier")
        self.accounts_tree.heading("usable_cap", text="Usable Cap (Post-Buffer)")
        self.accounts_tree.heading("used", text="Used Bytes")
        self.accounts_tree.heading("free", text="Free Space")
        self.accounts_tree.heading("status", text="Utilization")

        self.accounts_tree.column("priority", width=220, anchor="w")
        self.accounts_tree.column("account_name", width=140, anchor="w")
        self.accounts_tree.column("provider", width=130, anchor="w")
        self.accounts_tree.column("tier", width=80, anchor="center")
        self.accounts_tree.column("usable_cap", width=140, anchor="center")
        self.accounts_tree.column("used", width=100, anchor="center")
        self.accounts_tree.column("free", width=100, anchor="center")
        self.accounts_tree.column("status", width=110, anchor="center")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.accounts_tree.yview)
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)
        self.accounts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.accounts_tree.bind("<Button-3>", self._show_accounts_context_menu)
        self.accounts_tree.tag_configure("group_header", background="#1a1c2e", foreground="#38bdf8", font=("Segoe UI", 9, "bold"))

        # Manual Registration Card (With Confirmed Rclone Validation)
        add_frame = tk.LabelFrame(
            self.tab_accounts,
            text=" Manual Registration / Capacity Override (Validated against Rclone) ",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD,
            padx=14,
            pady=8,
            bd=1,
            relief="solid",
            highlightthickness=0
        )
        add_frame.pack(fill=tk.X, side=tk.BOTTOM)

        inputs_box = tk.Frame(add_frame, bg=BG_CARD)
        inputs_box.pack(fill=tk.X)

        tk.Label(inputs_box, text="Remote Name:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).grid(row=0, column=0, sticky="w", padx=4, pady=1)
        self.acc_name_combo = ttk.Combobox(inputs_box, values=[], width=15)
        self.acc_name_combo.grid(row=1, column=0, padx=4, pady=2)

        tk.Label(inputs_box, text="Provider:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).grid(row=0, column=1, sticky="w", padx=4, pady=1)
        self.provider_combo = ttk.Combobox(inputs_box, values=["Google Drive", "MEGA", "OneDrive", "Box", "Dropbox"], state="readonly", width=13)
        self.provider_combo.set("OneDrive")
        self.provider_combo.bind("<<ComboboxSelected>>", self._on_provider_selected)
        self.provider_combo.grid(row=1, column=1, padx=4, pady=2)

        tk.Label(inputs_box, text="Raw Size (GB):", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).grid(row=0, column=2, sticky="w", padx=4, pady=1)
        self.raw_gb_entry = tk.Entry(inputs_box, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, relief="flat", width=11)
        self.raw_gb_entry.insert(0, "20.0")
        self.raw_gb_entry.grid(row=1, column=2, padx=4, pady=2)

        tk.Label(inputs_box, text="Buffer (GB):", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).grid(row=0, column=3, sticky="w", padx=4, pady=1)
        self.buffer_gb_entry = tk.Entry(inputs_box, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, relief="flat", width=11)
        self.buffer_gb_entry.insert(0, "0.0")
        self.buffer_gb_entry.grid(row=1, column=3, padx=4, pady=2)

        tk.Label(inputs_box, text="Tier:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).grid(row=0, column=4, sticky="w", padx=4, pady=1)
        self.acc_tier_combo = ttk.Combobox(inputs_box, values=["STABLE", "VOLATILE"], state="readonly", width=10)
        self.acc_tier_combo.set("STABLE")
        self.acc_tier_combo.grid(row=1, column=4, padx=4, pady=2)

        tk.Label(inputs_box, text="Priority:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).grid(row=0, column=5, sticky="w", padx=4, pady=1)
        self.priority_entry = tk.Entry(inputs_box, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, relief="flat", width=8)
        self.priority_entry.insert(0, "1")
        self.priority_entry.grid(row=1, column=5, padx=4, pady=2)

        register_btn = tk.Button(
            inputs_box,
            text="➕ Register Remote",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_SUCCESS,
            fg=TEXT_WHITE,
            activebackground="#059669",
            activeforeground=TEXT_WHITE,
            relief="flat",
            padx=12,
            pady=3,
            cursor="hand2",
            command=self._on_register_account
        )
        register_btn.grid(row=1, column=6, padx=8, pady=2)

    # -------------------------------------------------------------
    # BOTTOM STATUS BAR
    # -------------------------------------------------------------
    def _build_bottom_status(self):
        status_bar = tk.Frame(self.root, bg=BG_CARD, padx=16, pady=5, bd=1, relief="solid")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.bottom_lbl = tk.Label(
            status_bar, 
            text="CloudPool Engine: Ready • Rclone Muscle: Integrated • AES-256-GCM + RAID-5 Active", 
            font=("Segoe UI", 8), 
            fg=TEXT_MUTED, 
            bg=BG_CARD
        )
        self.bottom_lbl.pack(side=tk.LEFT)

        author_lbl = tk.Label(
            status_bar, 
            text="Zero-Knowledge Single Virtual Pool Wrapper", 
            font=("Segoe UI", 8), 
            fg=TEXT_DIM, 
            bg=BG_CARD
        )
        author_lbl.pack(side=tk.RIGHT)

    # -------------------------------------------------------------
    # CONTEXT MENU & VFS NAVIGATION HANDLERS
    # -------------------------------------------------------------
    def _build_context_menu(self):
        self.context_menu = tk.Menu(
            self.root, 
            tearoff=0, 
            bg=BG_CARD, 
            fg=TEXT_WHITE,
            activebackground=ACCENT_PRIMARY, 
            activeforeground=TEXT_WHITE,
            font=("Segoe UI", 9)
        )

        self.accounts_context_menu = tk.Menu(
            self.root, 
            tearoff=0, 
            bg=BG_CARD, 
            fg=TEXT_WHITE,
            activebackground=ACCENT_PRIMARY, 
            activeforeground=TEXT_WHITE,
            font=("Segoe UI", 9)
        )
        self.accounts_context_menu.add_command(label="🗑️ Remove / Unregister Remote", command=self._on_unregister_account)
        self.accounts_context_menu.add_command(label="🩺 Test Remote Connectivity", command=self._on_test_connectivity)
        self.accounts_context_menu.add_separator()
        self.accounts_context_menu.add_command(label="🔄 Sync Remotes from rclone.conf", command=self._on_sync_rclone)

    def _show_accounts_context_menu(self, event):
        item_id = self.accounts_tree.identify_row(event.y)
        if item_id:
            item = self.accounts_tree.item(item_id)
            if "group_header" in item.get("tags", []):
                return
            self.accounts_tree.selection_set(item_id)
            try:
                self.accounts_context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.accounts_context_menu.grab_release()

    def _update_breadcrumbs(self):
        """Builds interactive breadcrumb navigation buttons: Vault > Folder > Subfolder."""
        if not hasattr(self, "breadcrumbs_frame"):
            return
        for widget in self.breadcrumbs_frame.winfo_children():
            widget.destroy()

        # Vault Root button
        root_pill = tk.Button(
            self.breadcrumbs_frame,
            text="🏠 Vault",
            font=("Segoe UI", 8, "bold" if self.current_folder_id is None else "normal"),
            bg=BG_CARD if self.current_folder_id is None else BG_CARD_LIGHT,
            fg=ACCENT_CYAN if self.current_folder_id is None else TEXT_WHITE,
            activebackground=BG_CARD,
            activeforeground=ACCENT_CYAN,
            relief="flat",
            padx=7,
            pady=2,
            cursor="hand2",
            command=lambda: self._enter_folder(None)
        )
        root_pill.pack(side=tk.LEFT, padx=1)

        if self.current_folder_id:
            ancestors = self.db.get_folder_path(self.current_folder_id)
            for idx, a in enumerate(ancestors):
                is_current = (idx == len(ancestors) - 1)
                sep = tk.Label(self.breadcrumbs_frame, text=">", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_DARK)
                sep.pack(side=tk.LEFT, padx=3)

                pill = tk.Button(
                    self.breadcrumbs_frame,
                    text=f"📁 {a['folder_name']}",
                    font=("Segoe UI", 8, "bold" if is_current else "normal"),
                    bg=BG_CARD if is_current else BG_CARD_LIGHT,
                    fg=ACCENT_CYAN if is_current else TEXT_WHITE,
                    activebackground=BG_CARD,
                    activeforeground=ACCENT_CYAN,
                    relief="flat",
                    padx=7,
                    pady=2,
                    cursor="hand2",
                    command=lambda fid=a["folder_id"]: self._enter_folder(fid)
                )
                pill.pack(side=tk.LEFT, padx=1)

    def _sort_column(self, col):
        """Sorts virtual files treeview by the clicked column (asc/desc toggle)."""
        reverse = self.sort_state.get(col, False)
        children = self.files_tree.get_children("")
        items = [(self.files_tree.set(k, col), k) for k in children]

        if col == "size":
            def parse_size(val):
                try:
                    parts = val[0].split()
                    if len(parts) == 2:
                        num = float(parts[0])
                        unit = parts[1].upper()
                        mult = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit, 1)
                        return num * mult
                except Exception:
                    pass
                return -1 if "item" in val[0] else 0

            items.sort(key=parse_size, reverse=reverse)
        elif col == "chunks":
            def parse_chunks(val):
                try:
                    return int(val[0].split()[0])
                except Exception:
                    return -1

            items.sort(key=parse_chunks, reverse=reverse)
        elif col == "name":
            def parse_name(val):
                is_file = 0 if val[0].startswith("📁") else 1
                return (is_file, val[0].lower())

            items.sort(key=parse_name, reverse=reverse)
        else:
            items.sort(key=lambda t: t[0].lower() if isinstance(t[0], str) else t[0], reverse=reverse)

        for idx, (val, k) in enumerate(items):
            self.files_tree.move(k, "", idx)

        # Flip toggle state
        self.sort_state[col] = not reverse

        # Update headings with arrow indicators
        for c, title in self.column_titles.items():
            if c == col:
                arrow = " ▼" if reverse else " ▲"
                self.files_tree.heading(c, text=title + arrow, command=lambda _c=c: self._sort_column(_c))
            else:
                self.files_tree.heading(c, text=title, command=lambda _c=c: self._sort_column(_c))

    def _run_preflight_ping(self):
        """Silently pings all registered remotes in the background on startup and updates status dots."""
        accounts = self.db.get_accounts()
        for a in accounts:
            name = a["account_name"]
            if not self.db.is_remote_in_rclone_config(name):
                self.remote_health_map[name] = {"status": "red", "msg": "Missing in rclone.conf"}
                self.msg_queue.put({"type": "remote_status_update"})
                continue

            cmd = [RCLONE_BIN, "lsd", f"{name}:", "--max-depth", "1"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    self.remote_health_map[name] = {"status": "green", "msg": "Online & Verified"}
                else:
                    err = res.stderr.strip().split("\n")[-1][:40] or "Auth Error"
                    self.remote_health_map[name] = {"status": "red", "msg": err}
            except Exception:
                self.remote_health_map[name] = {"status": "red", "msg": "Timeout"}

            self.msg_queue.put({"type": "remote_status_update"})

    def _show_context_menu(self, event):
        item_id = self.files_tree.identify_row(event.y)
        if item_id:
            self.files_tree.selection_set(item_id)
            vals = self.files_tree.item(item_id)["values"]
            is_folder = (vals[1] == "Virtual Folder")
            entity_id = str(vals[6])

            self.context_menu.delete(0, tk.END)
            if is_folder:
                self.context_menu.add_command(label="📁 Open Folder", command=lambda: self._enter_folder(entity_id))
                self.context_menu.add_command(label="➕ New Subfolder...", command=lambda: self._prompt_new_folder(parent_id=entity_id))
                self.context_menu.add_command(label="📦 Move Folder...", command=self._prompt_move)
                self.context_menu.add_command(label="✏️ Rename Folder", command=self._prompt_rename)
                self.context_menu.add_separator()
                self.context_menu.add_command(label="🗑️ Wipe Folder & Contents from Cloud", command=self._on_delete_selected)
            else:
                self.context_menu.add_command(label="📥 Download & Restore", command=self._on_download_selected)
                self.context_menu.add_command(label="📦 Move to Folder...", command=self._prompt_move)
                self.context_menu.add_command(label="✏️ Rename File", command=self._prompt_rename)
                self.context_menu.add_separator()
                self.context_menu.add_command(label="🗑️ True Wipe from Cloud", command=self._on_delete_selected)

            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()
        else:
            self.context_menu.delete(0, tk.END)
            self.context_menu.add_command(label="➕ New Folder Here", command=self._prompt_new_folder)
            self.context_menu.add_command(label="🔄 Refresh Vault", command=self.refresh_all_data)
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()

    def _enter_folder(self, folder_id):
        self.current_folder_id = folder_id
        self.search_query_var.set("")
        self._refresh_files_tree()
        self._sync_folder_tree_selection()

    def _nav_to_root(self):
        self.current_folder_id = None
        self.search_query_var.set("")
        self._refresh_files_tree()
        self._sync_folder_tree_selection()

    def _nav_up_level(self):
        if not self.current_folder_id:
            return
        folder = self.db.get_folder(self.current_folder_id)
        self.current_folder_id = folder["parent_folder_id"] if folder else None
        self.search_query_var.set("")
        self._refresh_files_tree()
        self._sync_folder_tree_selection()

    def _on_folder_tree_selected(self, event):
        selected = self.folder_tree.selection()
        if not selected:
            return
        item_id = selected[0]
        self.current_folder_id = None if item_id == "root" else item_id
        self.search_query_var.set("")
        self._refresh_files_tree()

    def _sync_folder_tree_selection(self):
        target_iid = self.current_folder_id if self.current_folder_id else "root"
        if hasattr(self, "folder_tree") and self.folder_tree.exists(target_iid):
            self.folder_tree.selection_set(target_iid)
            self.folder_tree.see(target_iid)

    def _on_table_double_click(self, event):
        selected = self.files_tree.selection()
        if not selected:
            return
        vals = self.files_tree.item(selected[0])["values"]
        is_folder = (vals[1] == "Virtual Folder")
        entity_id = str(vals[6])

        if is_folder:
            self._enter_folder(entity_id)
        else:
            self._on_download_selected()

    def _on_search_query_changed(self, event=None):
        self._refresh_files_tree()

    def _clear_search(self):
        self.search_query_var.set("")
        self._refresh_files_tree()

    def _dark_input_dialog(self, title, prompt, initialvalue="", show=None):
        """Displays a modal dark-mode input dialog with high-contrast text and inputs."""
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=BG_CARD)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        # Center on parent window
        dlg.geometry("440x190")
        try:
            self.root.update_idletasks()
            rx = self.root.winfo_rootx()
            ry = self.root.winfo_rooty()
            rw = self.root.winfo_width()
            rh = self.root.winfo_height()
            x = rx + (rw // 2) - 220
            y = ry + (rh // 2) - 95
            dlg.geometry(f"+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

        content = tk.Frame(dlg, bg=BG_CARD, padx=22, pady=18)
        content.pack(fill=tk.BOTH, expand=True)

        lbl = tk.Label(content, text=prompt, font=("Segoe UI", 9, "bold"), fg=TEXT_WHITE, bg=BG_CARD, justify=tk.LEFT, wraplength=390)
        lbl.pack(anchor="w", pady=(0, 10))

        entry_val = tk.StringVar(value=initialvalue)
        entry_kw = {
            "bg": BG_INPUT, 
            "fg": TEXT_WHITE, 
            "insertbackground": TEXT_WHITE, 
            "relief": "solid", 
            "bd": 1, 
            "highlightthickness": 1, 
            "highlightbackground": BORDER_COLOR, 
            "font": ("Segoe UI", 10)
        }
        if show:
            entry_kw["show"] = show
        entry = tk.Entry(content, textvariable=entry_val, **entry_kw)
        entry.pack(fill=tk.X, pady=(0, 16), ipady=4)
        entry.focus_set()
        if initialvalue:
            entry.select_range(0, tk.END)

        result = [None]

        def on_ok(event=None):
            result[0] = entry_val.get()
            dlg.destroy()

        def on_cancel(event=None):
            result[0] = None
            dlg.destroy()

        btn_box = tk.Frame(content, bg=BG_CARD)
        btn_box.pack(fill=tk.X)

        ok_btn = tk.Button(btn_box, text="  OK  ", font=("Segoe UI", 9, "bold"), bg=ACCENT_PRIMARY, fg=TEXT_WHITE, activebackground=ACCENT_HOVER, activeforeground=TEXT_WHITE, relief="flat", padx=16, pady=5, cursor="hand2", command=on_ok)
        ok_btn.pack(side=tk.RIGHT, padx=(8, 0))

        cancel_btn = tk.Button(btn_box, text="Cancel", font=("Segoe UI", 9), bg=BG_CARD_LIGHT, fg=TEXT_MUTED, activebackground=BG_CARD, activeforeground=TEXT_WHITE, relief="flat", padx=12, pady=5, cursor="hand2", command=on_cancel)
        cancel_btn.pack(side=tk.RIGHT)

        dlg.bind("<Return>", on_ok)
        dlg.bind("<Escape>", on_cancel)

        self.root.wait_window(dlg)
        return result[0]

    def _prompt_new_folder(self, parent_id=None):
        target_parent = parent_id if parent_id is not None else self.current_folder_id
        parent_path = self.db.get_folder_path_string(target_parent)
        folder_name = self._dark_input_dialog(
            "New Virtual Folder",
            f"Create folder inside: {parent_path}\n\nEnter folder name:"
        )
        if not folder_name or not folder_name.strip():
            return
        try:
            self.db.create_folder(folder_name.strip(), parent_folder_id=target_parent)
            self.log(f"Created virtual folder '{folder_name.strip()}' under '{parent_path}'")
            self.refresh_all_data()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create folder:\n{e}")

    def _prompt_rename(self):
        selected = self.files_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a file or folder to rename.")
            return

        item = self.files_tree.item(selected[0])
        vals = item["values"]
        is_folder = (vals[1] == "Virtual Folder")
        curr_name = vals[0].replace("📁 ", "").replace("📄 ", "").rstrip("/")
        entity_id = str(vals[6])

        entity_type = "Folder" if is_folder else "File"
        new_name = self._dark_input_dialog(
            f"Rename {entity_type}",
            f"Enter new name for {entity_type.lower()} '{curr_name}':",
            initialvalue=curr_name
        )
        if not new_name or not new_name.strip() or new_name.strip() == curr_name:
            return

        try:
            if is_folder:
                self.db.rename_folder(entity_id, new_name.strip())
                self.log(f"Renamed virtual folder '{curr_name}' -> '{new_name.strip()}'")
            else:
                self.db.rename_virtual_file(entity_id, new_name.strip())
                self.log(f"Renamed virtual file '{curr_name}' -> '{new_name.strip()}'")
            self.refresh_all_data()
        except Exception as e:
            messagebox.showerror("Rename Error", f"Failed to rename:\n{e}")

    def _prompt_move(self):
        selected = self.files_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a file or folder to move.")
            return

        item = self.files_tree.item(selected[0])
        vals = item["values"]
        is_folder = (vals[1] == "Virtual Folder")
        curr_name = vals[0].replace("📁 ", "").replace("📄 ", "").rstrip("/")
        entity_id = str(vals[6])

        # Destination selection window
        move_win = tk.Toplevel(self.root)
        move_win.title(f"Move '{curr_name}' to Folder")
        move_win.geometry("450x380")
        move_win.configure(bg=BG_DARK)
        move_win.transient(self.root)
        move_win.grab_set()

        tk.Label(
            move_win,
            text=f"Select Destination Folder for '{curr_name}':",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_WHITE,
            bg=BG_DARK,
            padx=12,
            pady=10
        ).pack(anchor="w")

        tree_box = tk.Frame(move_win, bg=BG_INPUT)
        tree_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        dest_tree = ttk.Treeview(tree_box, selectmode="browse", show="tree")
        d_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=dest_tree.yview)
        dest_tree.configure(yscrollcommand=d_scroll.set)
        dest_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        dest_tree.insert("", "end", iid="root", text="📁 / (Root Vault)", open=True)
        all_folders = self.db.get_all_folders()

        def add_subfolders(parent_id, parent_iid):
            subs = [f for f in all_folders if (f["parent_folder_id"] or None) == parent_id]
            for s in subs:
                fid = s["folder_id"]
                fname = s["folder_name"]
                if is_folder and fid == entity_id:
                    continue  # Can't move a folder into itself
                dest_tree.insert(parent_iid, "end", iid=fid, text=f"📁 {fname}", open=True)
                add_subfolders(fid, fid)

        add_subfolders(None, "root")
        dest_tree.selection_set("root")

        def do_move():
            sel = dest_tree.selection()
            if not sel:
                return
            target_iid = sel[0]
            target_fid = None if target_iid == "root" else target_iid
            try:
                if is_folder:
                    self.db.move_folder(entity_id, target_fid)
                    self.log(f"Moved virtual folder '{curr_name}' to '{self.db.get_folder_path_string(target_fid)}'")
                else:
                    self.db.move_file_to_folder(entity_id, target_fid)
                    self.log(f"Moved virtual file '{curr_name}' to '{self.db.get_folder_path_string(target_fid)}'")
                move_win.destroy()
                self.refresh_all_data()
            except Exception as ex:
                messagebox.showerror("Move Error", str(ex), parent=move_win)

        btn_box = tk.Frame(move_win, bg=BG_DARK, padx=12, pady=10)
        btn_box.pack(fill=tk.X)

        tk.Button(
            btn_box,
            text="Move Here",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_PRIMARY,
            fg=TEXT_WHITE,
            activebackground=ACCENT_HOVER,
            relief="flat",
            padx=14,
            pady=4,
            cursor="hand2",
            command=do_move
        ).pack(side=tk.RIGHT, padx=4)

        tk.Button(
            btn_box,
            text="Cancel",
            font=("Segoe UI", 9),
            bg=BG_CARD_LIGHT,
            fg=TEXT_MUTED,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
            command=move_win.destroy
        ).pack(side=tk.RIGHT, padx=4)

    # -------------------------------------------------------------
    # DRAG & DROP & BROWSE HANDLERS
    # -------------------------------------------------------------
    def _on_drag_enter(self, event):
        self.drop_frame.config(bg="#1e293b", highlightbackground="#38bdf8", highlightthickness=2)
        self.drop_icon.config(text="📥 ⚡", bg="#1e293b", fg="#38bdf8")
        self.drop_prompt.config(text="✨ Drop to Encrypt & Upload ✨", bg="#1e293b", fg="#38bdf8", font=("Segoe UI", 14, "bold"))
        self.drop_subtext.config(text="Release to stream directly into multi-core AES-256-GCM RAM pipeline", bg="#1e293b", fg="#94a3b8")

    def _on_drag_leave(self, event=None):
        self.drop_frame.config(bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.drop_icon.config(text="☁ ⬇", bg=BG_CARD, fg=ACCENT_PRIMARY)
        self.drop_prompt.config(text="Drag and Drop Files or Folders Here", bg=BG_CARD, fg=TEXT_WHITE, font=("Segoe UI", 13, "bold"))
        self.drop_subtext.config(text="Files and folders are zero-knowledge encrypted (AES-256-GCM), RAID-5 protected, and mapped into your Virtual File System.", bg=BG_CARD, fg=TEXT_MUTED)

    def _on_files_dropped(self, event):
        self._on_drag_leave(event)
        if self.is_busy:
            messagebox.showwarning("Busy", "A transfer is currently in progress. Please wait until it completes.")
            return

        raw_data = event.data
        if not raw_data:
            return

        files = self.root.tk.splitlist(raw_data)
        if not files:
            return

        self._start_upload_queue(list(files))

    def _browse_and_upload(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "A transfer is currently in progress. Please wait until it completes.")
            return

        selected = filedialog.askopenfilenames(title="Select File(s) to Encrypt & Pool")
        if selected:
            self._start_upload_queue(list(selected))

    def _browse_folder_and_upload(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "A transfer is currently in progress. Please wait until it completes.")
            return

        folder_selected = filedialog.askdirectory(title="Select Local Directory to Encrypt & Pool")
        if folder_selected:
            self._start_upload_queue([folder_selected])

    # -------------------------------------------------------------
    # MULTI-THREADED ASYNC UPLOAD ENGINE (FILES & FOLDERS)
    # -------------------------------------------------------------
    def _on_cancel_transfer(self):
        """Prompts user to confirm cancellation of ongoing transfer and initiates safe rollback."""
        if not self.is_busy:
            return

        confirm = messagebox.askyesno(
            "Cancel Active Transfer?",
            "Are you sure you want to cancel the ongoing transfer?\n\n"
            "• The transfer will stop immediately.\n"
            "• Any partial chunks uploaded to cloud remotes will be automatically wiped.\n"
            "• The SQLite database record will be rolled back cleanly.\n\n"
            "Cancel this transfer now?",
            parent=self.root
        )
        if not confirm:
            return

        self.log("[CANCELLATION REQUESTED] Cancelling transfer. Force-terminating active streams and rolling back...")
        self.status_detail_lbl.config(fg=ACCENT_DANGER)
        self.status_var.set("⏹️ Cancelling transfer & rolling back partial data...")
        self.chunk_progress_detail.set("Active Chunk: Rolling back partial chunks...")

        # Signal cancellation and kill child processes immediately
        self.net_engine.cancel_transfer()
        try:
            ProcessManager.kill_all_processes()
        except Exception:
            pass

    def _retry_last_failed_upload(self):
        """Retries the last failed upload batch without re-selecting files."""
        if self.is_busy:
            messagebox.showwarning("Busy", "A transfer is currently in progress.")
            return
        if not self.last_failed_upload or not self.last_failed_upload.get("paths"):
            messagebox.showinfo("No Failed Transfer", "There is no recent failed transfer to retry.")
            return

        params = self.last_failed_upload
        if hasattr(self, "retry_btn"):
            self.retry_btn.pack_forget()
        self.status_detail_lbl.config(fg=ACCENT_CYAN)
        names = [os.path.basename(p) for p in params["paths"]]
        self.log(f"[RETRY INITIATED] Retrying upload for {len(names)} item(s): {', '.join(names)}")
        self._start_upload_queue(params["paths"], target_folder_id=params.get("folder_id"))

    def _start_upload_queue(self, paths, target_folder_id=None):
        tier = "STABLE"  # Strict stable routing by default
        parity = self.enable_parity_var.get()

        valid_items = [p for p in paths if os.path.exists(p)]
        if not valid_items:
            messagebox.showerror("Error", "No valid files or directories were selected.")
            return

        if target_folder_id is None:
            combo_val = self.target_folder_combo.get()
            target_folder_id = self.folder_id_map.get(combo_val, None)

        # Reset cancellation flag and show Cancel Transfer button
        self.net_engine.cancel_requested = False
        if hasattr(self, "cancel_btn"):
            self.cancel_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Cache last upload parameters for in-line retry if needed
        self.last_failed_upload = {
            "paths": valid_items,
            "tier": tier,
            "parity": parity,
            "folder_id": target_folder_id
        }

        if hasattr(self, "retry_btn"):
            self.retry_btn.pack_forget()
        self.status_detail_lbl.config(fg=ACCENT_CYAN)

        dest_name = self.db.get_folder_path_string(target_folder_id)
        self.is_busy = True
        self.progress_val.set(0.0)
        self.progress_detail.set("0.0%")
        self.chunk_progress_val.set(0.0)
        self.chunk_progress_detail.set("Active Chunk: Preparing...")
        self.file_progress_var.set("Scanning items for upload...")
        self.speed_eta_var.set("⚡ Speed: Initializing...")
        self.log(f"Queued {len(valid_items)} item(s) -> '{dest_name}' (STABLE pool, RAID-5: {'ON' if parity else 'OFF'}).")

        worker_thread = threading.Thread(
            target=self._upload_worker,
            args=(valid_items, tier, parity, target_folder_id),
            daemon=True
        )
        worker_thread.start()

    def _upload_worker(self, paths, tier, enable_parity, target_folder_id):
        """Runs in background thread. Stream slices, encrypts, and uploads files or recursive folders."""
        try:
            # 1. Pre-scan total files and total bytes in batch
            total_batch_bytes = 0
            total_file_count = 0
            for p in paths:
                if os.path.isfile(p):
                    total_batch_bytes += os.path.getsize(p)
                    total_file_count += 1
                elif os.path.isdir(p):
                    for root, _, files in os.walk(p):
                        for f in files:
                            fp = os.path.join(root, f)
                            if os.path.exists(fp):
                                total_batch_bytes += os.path.getsize(fp)
                                total_file_count += 1

            total_file_count = max(1, total_file_count)
            total_batch_bytes = max(1, total_batch_bytes)
            batch_completed_bytes = 0
            current_file_idx = 0
            batch_start_time = time.time()

            for p in paths:
                if self.net_engine.cancel_requested:
                    break
                if os.path.isdir(p):
                    folder_name = os.path.basename(os.path.normpath(p))
                    self.msg_queue.put({
                        "type": "log",
                        "msg": f"Starting recursive upload for folder '{folder_name}'..."
                    })

                    def folder_cb(step, current, total, percent, account="", message="", **kwargs):
                        payload = {
                            "type": "progress",
                            "step": step,
                            "current": current,
                            "total": total,
                            "percent": percent,
                            "account": account,
                            "message": message,
                            "file_name": folder_name
                        }
                        payload.update(kwargs)
                        self.msg_queue.put(payload)

                    try:
                        self.net_engine.upload_folder(
                            p,
                            target_tier=tier,
                            parent_folder_id=target_folder_id,
                            progress_callback=folder_cb,
                            enable_parity=enable_parity,
                            batch_completed_bytes=batch_completed_bytes,
                            batch_total_bytes=total_batch_bytes,
                            file_index=current_file_idx,
                            total_files=total_file_count,
                            batch_start_time=batch_start_time,
                            defer_metadata_sync=True
                        )
                        f_size = sum(os.path.getsize(os.path.join(r, fn)) for r, _, fl in os.walk(p) for fn in fl if os.path.exists(os.path.join(r, fn)))
                        f_count = sum(len(fl) for _, _, fl in os.walk(p))
                        batch_completed_bytes += f_size
                        current_file_idx += f_count
                        self.msg_queue.put({
                            "type": "log",
                            "msg": f"COMPLETED: Folder '{folder_name}' and all sub-items safely sharded and mapped."
                        })
                    except Exception as e:
                        if not self.net_engine.cancel_requested:
                            self.msg_queue.put({
                                "type": "error",
                                "file_name": folder_name,
                                "error": str(e)
                            })
                        break

                elif os.path.isfile(p):
                    current_file_idx += 1
                    file_name = os.path.basename(p)
                    file_size = os.path.getsize(p)
                    self.msg_queue.put({
                        "type": "log",
                        "msg": f"Starting upload [{current_file_idx}/{total_file_count}] for '{file_name}' ({format_bytes(file_size)})"
                    })

                    def file_cb(step, current, total, percent, account="", message="", **kwargs):
                        payload = {
                            "type": "progress",
                            "step": step,
                            "current": current,
                            "total": total,
                            "percent": percent,
                            "account": account,
                            "message": message,
                            "file_name": file_name,
                            "file_index": current_file_idx,
                            "total_files": total_file_count
                        }
                        payload.update(kwargs)
                        self.msg_queue.put(payload)

                    try:
                        self.net_engine.upload_file(
                            p,
                            target_tier=tier,
                            target_folder_id=target_folder_id,
                            progress_callback=file_cb,
                            enable_parity=enable_parity,
                            batch_completed_bytes=batch_completed_bytes,
                            batch_total_bytes=total_batch_bytes,
                            file_index=current_file_idx,
                            total_files=total_file_count,
                            batch_start_time=batch_start_time,
                            defer_metadata_sync=True
                        )
                        batch_completed_bytes += file_size
                        self.msg_queue.put({
                            "type": "log",
                            "msg": f"COMPLETED: '{file_name}' safely sharded with AES-256-GCM + RAID-5 into STABLE pool."
                        })
                    except Exception as e:
                        if not self.net_engine.cancel_requested:
                            self.msg_queue.put({
                                "type": "error",
                                "file_name": file_name,
                                "error": str(e)
                            })
                        break
        except Exception as e:
            if not self.net_engine.cancel_requested:
                self.msg_queue.put({
                    "type": "error",
                    "file_name": "Upload Batch",
                    "error": str(e)
                })
        finally:
            if self.net_engine.cancel_requested:
                self.msg_queue.put({"type": "upload_cancelled"})
            else:
                # Deferred Metadata Mirroring: runs exactly ONCE when the entire batch is complete
                try:
                    MetadataEngine.sync_metadata_to_cloud(self.db)
                except Exception as sync_err:
                    print(f"[METADATA] Deferred batch sync warning: {sync_err}")
                self.msg_queue.put({"type": "upload_finished"})

    # -------------------------------------------------------------
    # MULTI-THREADED ASYNC DOWNLOAD ENGINE (FILES & FOLDERS)
    # -------------------------------------------------------------
    def _on_download_selected(self):
        selected = self.files_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a virtual file or folder to download.")
            return

        if self.is_busy:
            messagebox.showwarning("Busy", "Another transfer operation is currently running.")
            return

        item = self.files_tree.item(selected[0])
        vals = item["values"]
        is_folder = (vals[1] == "Virtual Folder")
        entity_name = vals[0].replace("📁 ", "").replace("📄 ", "").rstrip("/")
        entity_id = str(vals[6])

        if is_folder:
            folder_id = entity_id
            folder_name = entity_name
            container = self.db.get_folder_container(folder_id)
            descendant_files = self.db.get_descendant_files(folder_id)
            if not container and not descendant_files:
                messagebox.showinfo("Empty Folder", f"Virtual folder '{folder_name}' does not contain any files.")
                return

            dest_dir = filedialog.askdirectory(title=f"Choose Destination Folder to Restore All Files in '{folder_name}'")
            if not dest_dir:
                return

            self.net_engine.cancel_requested = False
            if hasattr(self, "cancel_btn"):
                self.cancel_btn.pack(side=tk.RIGHT, padx=(0, 10))

            self.is_busy = True
            self.notebook.select(self.tab_upload)
            count_info = f"{len(descendant_files)} file(s)" if descendant_files else "virtual archive"
            self.log(f"Queued fast download for {count_info} in folder '{folder_name}' -> '{dest_dir}'")

            worker_thread = threading.Thread(
                target=self._download_folder_worker,
                args=(folder_id, folder_name, dest_dir),
                daemon=True
            )
            worker_thread.start()

        else:
            file_name = entity_name
            file_id = entity_id
            dest_dir = filedialog.askdirectory(title=f"Choose Destination Folder to Restore '{file_name}'")
            if not dest_dir:
                return

            self.net_engine.cancel_requested = False
            if hasattr(self, "cancel_btn"):
                self.cancel_btn.pack(side=tk.RIGHT, padx=(0, 10))

            self.is_busy = True
            self.notebook.select(self.tab_upload)
            self.log(f"Queued download for '{file_name}' into '{dest_dir}'")

            worker_thread = threading.Thread(
                target=self._download_worker,
                args=(file_id, file_name, dest_dir),
                daemon=True
            )
            worker_thread.start()

    def _download_folder_worker(self, folder_id, folder_name, dest_dir):
        """Runs in background thread. Fast downloads and extracts virtual archive or downloads subtree files."""
        try:
            def progress_callback(step, current, total, percent, account="", message="", **kwargs):
                payload = {
                    "type": "progress",
                    "step": step,
                    "current": current,
                    "total": total,
                    "percent": percent,
                    "account": account,
                    "message": message,
                    "file_name": folder_name
                }
                payload.update(kwargs)
                self.msg_queue.put(payload)

            restored_path = self.net_engine.download_folder(folder_id, restore_folder=dest_dir, progress_callback=progress_callback)
            if not self.net_engine.cancel_requested:
                self.msg_queue.put({
                    "type": "download_success",
                    "path": restored_path,
                    "file_name": folder_name
                })
        except Exception as e:
            if not self.net_engine.cancel_requested:
                self.msg_queue.put({
                    "type": "error",
                    "file_name": folder_name,
                    "error": str(e)
                })
        finally:
            if self.net_engine.cancel_requested:
                self.msg_queue.put({"type": "download_cancelled"})
            else:
                self.msg_queue.put({"type": "download_finished"})

    def _download_worker(self, file_id, file_name, dest_dir):
        """Runs in background thread. Downloads chunks and executes RAID-5 XOR self-healing if needed."""
        try:
            def progress_callback(step, current, total, percent, account="", message=""):
                self.msg_queue.put({
                    "type": "progress",
                    "step": step,
                    "current": current,
                    "total": total,
                    "percent": percent,
                    "account": account,
                    "message": message,
                    "file_name": file_name
                })

            restored_path = self.net_engine.download_file(file_id, restore_folder=dest_dir, progress_callback=progress_callback)
            if not self.net_engine.cancel_requested:
                self.msg_queue.put({
                    "type": "download_success",
                    "path": restored_path,
                    "file_name": file_name
                })
        except Exception as e:
            if not self.net_engine.cancel_requested:
                self.msg_queue.put({
                    "type": "error",
                    "file_name": file_name,
                    "error": str(e)
                })
        finally:
            if self.net_engine.cancel_requested:
                self.msg_queue.put({"type": "download_cancelled"})
            else:
                self.msg_queue.put({"type": "download_finished"})

    # -------------------------------------------------------------
    # MULTI-THREADED ASYNC TRUE DELETION & SPACE RECLAMATION
    # -------------------------------------------------------------
    def _on_delete_selected(self):
        selected = self.files_tree.selection()
        if not selected:
            f_sel = self.folder_tree.selection()
            if f_sel and f_sel[0] != "root":
                entity_id = f_sel[0]
                folder = self.db.get_folder(entity_id)
                if folder:
                    self._delete_folder_prompt(entity_id, folder["folder_name"])
                return
            messagebox.showinfo("Selection Required", "Please select a file or folder to delete.")
            return

        if self.is_busy:
            messagebox.showwarning("Busy", "A transfer operation is currently in progress.")
            return

        item = self.files_tree.item(selected[0])
        vals = item["values"]
        is_folder = (vals[1] == "Virtual Folder")
        entity_name = vals[0].replace("📁 ", "").replace("📄 ", "").rstrip("/")
        entity_id = str(vals[6])

        if is_folder:
            self._delete_folder_prompt(entity_id, entity_name)
        else:
            self._delete_file_prompt(entity_id, entity_name)

    def _delete_file_prompt(self, file_id, file_name):
        confirm = messagebox.askyesno(
            "Confirm Remote Wipe & Space Reclamation",
            f"Are you sure you want to permanently delete '{file_name}'?\n\n"
            f"• Physically deletes every encrypted chunk and parity block across cloud remotes.\n"
            f"• Reclaims the exact storage quota in your pool.\n"
            f"• Mirrors the updated metadata to the cloud."
        )
        if not confirm:
            return

        self.is_busy = True
        self.notebook.select(self.tab_upload)
        self.log(f"Initiating true remote wipe for '{file_name}'...")

        worker_thread = threading.Thread(
            target=self._delete_worker,
            args=(file_id, file_name),
            daemon=True
        )
        worker_thread.start()

    def _delete_folder_prompt(self, folder_id, folder_name):
        descendant_files = self.db.get_descendant_files(folder_id)
        count = len(descendant_files)

        confirm = messagebox.askyesno(
            "Confirm Folder Wipe & Space Reclamation",
            f"Are you sure you want to permanently delete virtual folder '{folder_name}'?\n\n"
            f"• Contains {count} file(s) across this directory and subdirectories.\n"
            f"• All encrypted chunks on cloud remotes will be permanently wiped.\n"
            f"• Pool space will be fully reclaimed."
        )
        if not confirm:
            return

        self.is_busy = True
        self.notebook.select(self.tab_upload)
        self.log(f"Initiating recursive wipe for folder '{folder_name}' ({count} files)...")

        worker_thread = threading.Thread(
            target=self._delete_folder_worker,
            args=(folder_id, folder_name),
            daemon=True
        )
        worker_thread.start()

    def _delete_worker(self, file_id, file_name):
        """Runs in background thread. Commands Rclone to delete remote files and recovers space in SQLite."""
        def progress_callback(step, current, total, percent, account="", message=""):
            self.msg_queue.put({
                "type": "progress",
                "step": step,
                "current": current,
                "total": total,
                "percent": percent,
                "account": account,
                "message": message,
                "file_name": file_name
            })

        try:
            res = self.net_engine.delete_file(file_id, progress_callback=progress_callback)
            status = res.get("status") if isinstance(res, dict) else "completed"
            if status == "completed":
                self.msg_queue.put({
                    "type": "delete_success",
                    "file_name": file_name,
                    "deleted_chunks": res.get("deleted_chunks", 0)
                })
            elif status == "partially_deleted":
                self.msg_queue.put({
                    "type": "delete_partial",
                    "file_id": file_id,
                    "file_name": file_name,
                    "deleted": res.get("deleted_chunks", 0),
                    "failed": res.get("failed_chunks", 0),
                    "error_message": res.get("error_message", "Some chunks failed remote deletion.")
                })
            elif status == "failed":
                self.msg_queue.put({
                    "type": "delete_failed",
                    "file_id": file_id,
                    "file_name": file_name,
                    "failed": res.get("failed_chunks", 0),
                    "error_message": res.get("error_message", "Remote deletion failed.")
                })
        except Exception as e:
            self.msg_queue.put({
                "type": "error",
                "file_name": file_name,
                "error": str(e)
            })

        self.msg_queue.put({"type": "delete_finished"})

    def _delete_folder_worker(self, folder_id, folder_name):
        """Runs in background thread. Wipes all files in folder subtree and deletes folder records."""
        def progress_callback(step, current, total, percent, account="", message=""):
            self.msg_queue.put({
                "type": "progress",
                "step": step,
                "current": current,
                "total": total,
                "percent": percent,
                "account": account,
                "message": message,
                "file_name": folder_name
            })

        try:
            res = self.net_engine.delete_virtual_folder(folder_id, progress_callback=progress_callback)
            status = res.get("status") if isinstance(res, dict) else "completed"
            if status == "completed":
                self.msg_queue.put({
                    "type": "delete_success",
                    "file_name": f"Folder: {folder_name}"
                })
            elif status == "partially_deleted":
                self.msg_queue.put({
                    "type": "delete_partial",
                    "file_id": folder_id,
                    "file_name": f"Folder: {folder_name}",
                    "deleted": res.get("deleted_files", 0),
                    "failed": res.get("failed_files", 0),
                    "error_message": "Some files or chunks in the folder could not be deleted from remote accounts."
                })
            else:
                self.msg_queue.put({
                    "type": "delete_failed",
                    "file_id": folder_id,
                    "file_name": f"Folder: {folder_name}",
                    "failed": 1,
                    "error_message": "Remote deletion failed for folder container."
                })
        except Exception as e:
            self.msg_queue.put({
                "type": "error",
                "file_name": folder_name,
                "error": str(e)
            })

        self.msg_queue.put({"type": "delete_finished"})

    # -------------------------------------------------------------
    # METADATA MIRRORING & DISASTER RECOVERY
    # -------------------------------------------------------------
    def _on_manual_metadata_sync(self):
        """Manually mirrors encrypted metadata database to 2 cloud accounts using user recovery passphrase."""
        passphrase = self._dark_input_dialog(
            "Metadata Backup Passphrase",
            "Enter a secure passphrase to encrypt your cloud metadata backup:",
            show="*"
        )
        if not passphrase:
            return

        self.log("[METADATA] Packaging and encrypting database + master key with PBKDF2 (600,000 iters)...")
        remotes = MetadataEngine.sync_metadata_to_cloud(self.db, passphrase=passphrase)
        if remotes:
            msg = f"Encrypted metadata database mirrored successfully to: {', '.join(remotes)}"
            self.log(f"[METADATA SUCCESS] {msg}")
            messagebox.showinfo("Metadata Mirrored", msg)
        else:
            self.log("[METADATA WARNING] No accounts available for metadata mirroring.")
            messagebox.showwarning("Mirroring Failed", "Could not mirror metadata. Ensure at least one remote is active.")

    def _on_disaster_recovery(self):
        """Single-command recovery of master.key and database from cloud backup."""
        passphrase = self._dark_input_dialog(
            "Disaster Recovery Passphrase",
            "Enter your CloudPool Master Passphrase to decrypt the cloud backup:",
            show="*"
        )
        if not passphrase:
            return

        self.log("[DISASTER RECOVERY] Scanning remotes for encrypted metadata archive...")
        try:
            source_remote = MetadataEngine.restore_metadata_from_cloud(passphrase)
            self.log(f"[DISASTER RECOVERY SUCCESS] Restored database & master key from {source_remote}!")
            messagebox.showinfo(
                "Restoration Complete",
                f"Your CloudPool master database and encryption key were successfully recovered from '{source_remote}'!\n\n"
                f"The application will now reload your virtual pool."
            )
            self.refresh_all_data()
        except Exception as e:
            self.log(f"[DISASTER RECOVERY FAILED] {e}")
            messagebox.showerror("Recovery Failed", f"Failed to restore metadata:\n\n{e}\n\nCheck your passphrase and rclone.conf.")

    def _on_window_close(self):
        """
        Hard Kill-Switch Termination Protocol:
        Immediately stops all active transfers, forcefully terminates all child rclone.exe
        processes via OS-level taskkill, safely commits/closes database, flushes RAM buffers,
        and guarantees zero lingering background processes or persistence.
        """
        if self.is_busy:
            confirm = messagebox.askyesno(
                "Active Transfer in Progress",
                "An upload or download is currently streaming in memory.\n\n"
                "Closing CloudPool now will cancel the transfer and safely discard RAM buffers.\n\n"
                "Exit anyway?",
                parent=self.root
            )
            if not confirm:
                return

        # Display psychological and practical assurance teardown overlay
        teardown_dlg = tk.Toplevel(self.root)
        teardown_dlg.title("CloudPool Teardown")
        teardown_dlg.geometry("420x155")
        teardown_dlg.configure(bg=BG_CARD)
        teardown_dlg.transient(self.root)
        teardown_dlg.grab_set()
        teardown_dlg.resizable(False, False)

        try:
            teardown_dlg.update_idletasks()
            x = self.root.winfo_x() + (self.root.winfo_width() - 420) // 2
            y = self.root.winfo_y() + (self.root.winfo_height() - 155) // 2
            teardown_dlg.geometry(f"+{x}+{y}")
        except Exception:
            pass

        tk.Label(
            teardown_dlg,
            text="🔒 Safely Closing CloudPool",
            font=("Segoe UI", 12, "bold"),
            fg=TEXT_WHITE,
            bg=BG_CARD
        ).pack(pady=(16, 4))

        tk.Label(
            teardown_dlg,
            text="Safely closing connections, flushing RAM buffers,\nand terminating child Rclone processes...",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            justify="center"
        ).pack(pady=4)

        teardown_bar = ttk.Progressbar(teardown_dlg, mode="indeterminate", style="Cloud.Horizontal.TProgressbar")
        teardown_bar.pack(fill=tk.X, padx=30, pady=(6, 12))
        teardown_bar.start(10)
        teardown_dlg.update()

        def execute_teardown():
            # 1. Engage Absolute Kill-Switch on all child Rclone processes
            try:
                ProcessManager.kill_all_processes()
            except Exception:
                pass

            # 2. Silently sync metadata to cloud if not busy
            if not self.is_busy:
                try:
                    MetadataEngine.sync_metadata_to_cloud(self.db)
                except Exception:
                    pass

            # 3. Safely close database connection
            try:
                if hasattr(self, 'db') and self.db and hasattr(self.db, 'conn') and self.db.conn:
                    self.db.conn.close()
            except Exception:
                pass

            # 4. Destroy UI window
            try:
                self.root.destroy()
            except Exception:
                pass

            # 5. Flush memory and invoke garbage collection
            import gc
            gc.collect()

            # 6. Immediate OS-level termination to guarantee zero background persistence
            os._exit(0)

        self.root.after(750, execute_teardown)

    # -------------------------------------------------------------
    # THREAD-SAFE QUEUE PROCESSOR
    # -------------------------------------------------------------
    def _process_queue(self):
        """Processes messages emitted by background worker threads to keep UI at 60 FPS."""
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                mtype = msg.get("type")

                if mtype == "progress":
                    percent = msg.get("percent", 0.0)
                    chunk_pct = msg.get("chunk_percent", 0.0)
                    message = msg.get("message", "")
                    current = msg.get("current", 0)
                    total = msg.get("total", 0)
                    account = msg.get("account", "")

                    completed_bytes = msg.get("completed_bytes", None)
                    total_bytes = msg.get("total_bytes", None)
                    remaining_bytes = msg.get("remaining_bytes", None)
                    speed_bps = msg.get("speed_bps", None)
                    eta_seconds = msg.get("eta_seconds", None)
                    file_idx = msg.get("file_index", None)
                    tot_files = msg.get("total_files", None)

                    self.progress_val.set(percent)
                    self.progress_detail.set(f"{percent:.1f}%")
                    self.chunk_progress_val.set(chunk_pct)
                    self.status_var.set(message)
                    self.status_detail_lbl.config(fg=ACCENT_CYAN)

                    # Update Chunk Sub-bar text
                    if account:
                        self.chunk_progress_detail.set(f"Active Chunk: Part {current}/{total} • Streaming to {account} ({chunk_pct:.1f}%)")
                    elif total > 0:
                        self.chunk_progress_detail.set(f"Active Chunk: Part {current}/{total} ({chunk_pct:.1f}%)")

                    # 1. Update explicit completed vs remaining files and sizes
                    if tot_files is not None and file_idx is not None and tot_files > 0:
                        files_rem = max(0, tot_files - file_idx)
                        files_txt = f"Files: {file_idx}/{tot_files} ({files_rem} remaining)"
                    else:
                        files_txt = f"Chunks: {current}/{total}"

                    if completed_bytes is not None and total_bytes is not None and total_bytes > 0:
                        rem_b = remaining_bytes if remaining_bytes is not None else max(0, total_bytes - completed_bytes)
                        bytes_txt = f"{format_bytes(completed_bytes)} / {format_bytes(total_bytes)} ({format_bytes(rem_b)} remaining)"
                        self.file_progress_var.set(f"{files_txt} • {bytes_txt}")
                    else:
                        self.file_progress_var.set(files_txt)

                    # 2. Update real-time transfer speed & ETA
                    if speed_bps is not None and speed_bps > 0:
                        spd_txt = f"⚡ {format_bytes(speed_bps)}/s"
                        if eta_seconds is not None and eta_seconds >= 0:
                            m, s = divmod(int(eta_seconds), 60)
                            eta_txt = f"⏳ ETA: {m:02d}:{s:02d}" if m > 0 else f"⏳ ETA: {s}s"
                        else:
                            eta_txt = "⏳ ETA: Calculating..."
                        self.speed_eta_var.set(f"{spd_txt} • {eta_txt}")
                    else:
                        self.speed_eta_var.set("⚡ Speed: -- • ⏳ ETA: --")

                    if message:
                        self.log(message)

                elif mtype == "log":
                    self.log(msg.get("msg", ""))

                elif mtype == "error":
                    file_name = msg.get("file_name", "File")
                    err = msg.get("error", "Unknown error")
                    self.status_var.set(f"Transfer Failed: {err[:75]}")
                    self.status_detail_lbl.config(fg=ACCENT_DANGER)
                    self.chunk_progress_detail.set(f"Active Chunk: Interrupted on '{file_name}'")
                    self.log(f"[TRANSFER ERROR] {file_name}: {err}")
                    if hasattr(self, "cancel_btn"):
                        self.cancel_btn.pack_forget()
                    if hasattr(self, "retry_btn"):
                        self.retry_btn.pack(side=tk.RIGHT, padx=6)

                elif mtype in ("upload_cancelled", "download_cancelled"):
                    self.is_busy = False
                    if hasattr(self, "cancel_btn"):
                        self.cancel_btn.pack_forget()
                    self.progress_val.set(0.0)
                    self.progress_detail.set("0.0% • Cancelled")
                    self.chunk_progress_val.set(0.0)
                    self.chunk_progress_detail.set("Active Chunk: Cancelled & rolled back")
                    self.speed_eta_var.set("⚡ Speed: -- • ⏳ ETA: --")
                    self.file_progress_var.set("Transfer stopped by user. Partial chunks purged.")
                    self.status_var.set("⏹️ Transfer Cancelled — Partial data safely rolled back.")
                    self.status_detail_lbl.config(fg=ACCENT_DANGER)
                    self.net_engine.cancel_requested = False
                    self.log("[CANCELLED] Transfer stopped by user. All partial cloud chunks wiped and SQLite database restored.")
                    self.refresh_all_data()

                elif mtype == "download_success":
                    restored_path = msg.get("path")
                    file_name = msg.get("file_name")
                    self.log(f"[SUCCESS] Download & decryption complete: {restored_path}")
                    messagebox.showinfo(
                        "Download Complete",
                        f"File '{file_name}' was successfully downloaded, decrypted, and stitched!\n\nSaved to: {restored_path}"
                    )

                elif mtype == "delete_success":
                    file_name = msg.get("file_name")
                    self.log(f"[SUCCESS] Remote chunks for '{file_name}' confirmed wiped and storage reclaimed.")
                    self.refresh_all_data()
                    messagebox.showinfo(
                        "File Wiped Successfully",
                        f"'{file_name}' has been completely deleted from your cloud accounts.\n\nAll remote chunks were confirmed removed and pool space was reclaimed!"
                    )

                elif mtype == "delete_partial":
                    file_id = msg.get("file_id")
                    file_name = msg.get("file_name")
                    deleted_cnt = msg.get("deleted", 0)
                    failed_cnt = msg.get("failed", 0)
                    err_msg = msg.get("error_message", "")
                    self.log(f"[PARTIAL DELETION] '{file_name}': {deleted_cnt} chunks wiped, {failed_cnt} failed ({err_msg})")
                    self.refresh_all_data()
                    retry = messagebox.askyesno(
                        "Partial Deletion — Retry Remaining Chunks?",
                        f"Deletion for '{file_name}' is partially complete:\n\n"
                        f"• {deleted_cnt} chunk(s) confirmed deleted & quota reclaimed.\n"
                        f"• {failed_cnt} chunk(s) failed to delete.\n\n"
                        f"Failure Details:\n{err_msg[:200]}\n\n"
                        f"Metadata for the remaining {failed_cnt} chunk(s) has been safely preserved in your vault.\n\n"
                        f"Would you like to retry deleting the remaining chunks now?",
                        parent=self.root
                    )
                    if retry and file_id:
                        self.log(f"[RETRY DELETION] Retrying deletion for '{file_name}'...")
                        self._delete_file_prompt(file_id, file_name)

                elif mtype == "delete_failed":
                    file_id = msg.get("file_id")
                    file_name = msg.get("file_name")
                    err_msg = msg.get("error_message", "Remote cloud error")
                    self.log(f"[DELETION FAILED] '{file_name}': Remote deletion failed ({err_msg})")
                    self.refresh_all_data()
                    messagebox.showerror(
                        "Deletion Failed",
                        f"Could not delete '{file_name}' from remote cloud accounts:\n\n"
                        f"{err_msg[:300]}\n\n"
                        f"• All file metadata and chunks have been preserved in your vault.\n"
                        f"• Storage quota was NOT decremented.\n"
                        f"• You can retry deletion when the remotes are online.",
                        parent=self.root
                    )

                elif mtype in ("upload_finished", "download_finished", "delete_finished"):
                    self.is_busy = False
                    if hasattr(self, "cancel_btn"):
                        self.cancel_btn.pack_forget()
                    if mtype == "upload_finished":
                        self.progress_val.set(100.0)
                        self.progress_detail.set("100.0%")
                        self.chunk_progress_val.set(100.0)
                        self.chunk_progress_detail.set("Active Chunk: All chunks encrypted, streamed & verified.")
                        self.status_var.set("All transfers complete! Virtual pool updated.")
                        self.status_detail_lbl.config(fg=ACCENT_SUCCESS)
                        self.speed_eta_var.set("⚡ Complete")
                        self.file_progress_var.set("All items successfully encrypted, sharded, and pooled.")
                        if hasattr(self, "retry_btn"):
                            self.retry_btn.pack_forget()
                    else:
                        self.progress_val.set(0.0)
                        self.progress_detail.set("0.0% • Idle")
                        self.chunk_progress_val.set(0.0)
                        self.chunk_progress_detail.set("Active Chunk: Idle")
                        self.speed_eta_var.set("⚡ Speed: -- • ⏳ ETA: --")
                    self.refresh_all_data()

                elif mtype == "remote_status_update":
                    self._refresh_accounts_tree()

                elif mtype == "health_check_complete":
                    all_good = msg.get("all_good", False)
                    report = msg.get("report", "")
                    title = "Remote Health Check Complete" if all_good else "Remote Health Check - Warnings Detected"
                    if all_good:
                        messagebox.showinfo(title, f"All registered remotes are healthy and reachable!\n\n{report}")
                    else:
                        messagebox.showwarning(title, f"One or more remotes encountered issues:\n\n{report}")

        except queue.Empty:
            pass
        finally:
            self.root.after(35, self._process_queue)

    def log(self, text):
        """Appends a timestamped log entry to the UI text console."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.config(state=tk.NORMAL)
        self.log_box.insert(tk.END, f"[{timestamp}] {text}\n")
        self.log_box.see(tk.END)
        self.log_box.config(state=tk.DISABLED)

    # -------------------------------------------------------------
    # DATA REFRESH & AGGREGATION
    # -------------------------------------------------------------
    def refresh_all_data(self):
        """Queries SQLite and refreshes accounts, virtual files, folders, and summary badges."""
        self.db.sync_from_rclone_config()
        self._refresh_summary()
        self._refresh_target_folder_combo()
        self._refresh_folder_tree()
        self._refresh_files_tree()
        self._refresh_accounts_tree()

    def _refresh_summary(self):
        summary = self.db.get_pool_summary()
        total_usable = summary["total_usable"]
        total_used = summary["total_used"]
        free_bytes = summary["free_bytes"]
        acc_count = summary["account_count"]
        file_count = summary["file_count"]
        folder_count = summary.get("folder_count", 0)

        util_pct = (total_used / max(1, total_usable)) * 100.0
        if hasattr(self, "pool_quota_val"):
            self.pool_quota_val.set(util_pct)
        if hasattr(self, "pool_quota_text"):
            self.pool_quota_text.set(
                f"Unified Storage Pool: {format_bytes(total_used)} / {format_bytes(total_usable)} Used ({util_pct:.1f}%) • {format_bytes(free_bytes)} Free across {acc_count} Remotes"
            )
        if hasattr(self, "quota_pct_lbl"):
            self.quota_pct_lbl.config(text=f"{util_pct:.1f}% Used")

        text = (
            f"Pool: {format_bytes(total_usable)} Usable  |  "
            f"Used: {format_bytes(total_used)}  |  "
            f"Free: {format_bytes(free_bytes)}\n"
            f"Remotes: {acc_count} Connected  |  Files: {file_count}  |  Folders: {folder_count}"
        )
        self.pool_summary_var.set(text)

    def _refresh_target_folder_combo(self):
        """Rebuilds list of virtual folders for upload destination dropdown."""
        all_folders = self.db.get_all_folders()
        self.folder_id_map = {"📁 / (Root)": None}
        display_list = ["📁 / (Root)"]

        for f in all_folders:
            path_str = self.db.get_folder_path_string(f["folder_id"])
            display_name = f"📁 {path_str}"
            self.folder_id_map[display_name] = f["folder_id"]
            display_list.append(display_name)

        self.folder_display_list = display_list
        if hasattr(self, "target_folder_combo"):
            curr_val = self.target_folder_combo.get()
            self.target_folder_combo.config(values=display_list)
            if curr_val in display_list:
                self.target_folder_combo.set(curr_val)
            else:
                self.target_folder_combo.set("📁 / (Root)")

    def _refresh_folder_tree(self):
        """Populates hierarchical left treeview with nested folders."""
        if not hasattr(self, "folder_tree"):
            return
        for item in self.folder_tree.get_children():
            self.folder_tree.delete(item)

        # Root node
        self.folder_tree.insert("", "end", iid="root", text="📁 Vault Root (/)", open=True)
        all_folders = self.db.get_all_folders()

        def add_subfolders(parent_id, parent_iid):
            subs = [f for f in all_folders if (f["parent_folder_id"] or None) == parent_id]
            for s in subs:
                fid = s["folder_id"]
                fname = s["folder_name"]
                self.folder_tree.insert(parent_iid, "end", iid=fid, text=f"📁 {fname}", open=True)
                add_subfolders(fid, fid)

        add_subfolders(None, "root")
        self._sync_folder_tree_selection()

    def _refresh_files_tree(self):
        """Populates the right directory contents table with folders and files."""
        if not hasattr(self, "files_tree"):
            return
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)

        # Update clickable breadcrumbs
        self._update_breadcrumbs()

        query = self.search_query_var.get().strip()

        if query:
            # Search Results Mode
            search_data = self.db.search_vfs(query)
            folders = search_data["folders"]
            files = search_data["files"]
            total_matches = len(folders) + len(files)

            self.path_display_var.set(f"🔍 Search Results for '{query}' ({total_matches} found)")

            for f in folders:
                self.files_tree.insert(
                    "",
                    tk.END,
                    values=(
                        f"📁 {f['folder_name']}/",
                        "Virtual Folder",
                        f"Path: {f['path_str']}",
                        "—",
                        "—",
                        f.get("created_at", ""),
                        f["folder_id"]
                    )
                )

            for fl in files:
                parity_label = "✅ Protected (RAID-5)" if fl.get("has_parity") else "⚠️ No Parity"
                ext = fl['file_name'].split('.')[-1].upper() if '.' in fl['file_name'] else "File"
                self.files_tree.insert(
                    "",
                    tk.END,
                    values=(
                        f"📄 {fl['file_name']}",
                        ext,
                        format_bytes(fl["total_size_bytes"]),
                        f"{fl['chunk_count']} chunk(s)",
                        parity_label,
                        f"Path: {fl.get('path_str', '/')}",
                        fl["file_id"]
                    )
                )

        else:
            # Normal Directory Navigation Mode
            path_str = self.db.get_folder_path_string(self.current_folder_id)
            self.path_display_var.set(f"📁 Location: {path_str}")

            contents = self.db.get_directory_contents(self.current_folder_id)

            # 1. Folders first
            for f in contents["folders"]:
                self.files_tree.insert(
                    "",
                    tk.END,
                    values=(
                        f"📁 {f['folder_name']}/",
                        "Virtual Folder",
                        f"{f['total_items']} item(s)",
                        "—",
                        "—",
                        f.get("created_at", ""),
                        f["folder_id"]
                    )
                )

            # 2. Files second
            for fl in contents["files"]:
                del_status = fl.get("deletion_status", "active")
                if del_status == "partially_deleted":
                    parity_label = "⚠️ Partially Deleted (Retry)"
                elif del_status == "failed":
                    parity_label = "❌ Deletion Failed (Retry)"
                elif fl.get("has_parity"):
                    parity_label = "✅ Protected (RAID-5)"
                else:
                    parity_label = "⚠️ No Parity"
                ext = fl['file_name'].split('.')[-1].upper() if '.' in fl['file_name'] else "File"
                self.files_tree.insert(
                    "",
                    tk.END,
                    values=(
                        f"📄 {fl['file_name']}",
                        ext,
                        format_bytes(fl["total_size_bytes"]),
                        f"{fl['chunk_count']} chunk(s)",
                        parity_label,
                        fl["uploaded_at"],
                        fl["file_id"]
                    )
                )

    def _refresh_accounts_tree(self):
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)

        accounts = self.db.get_accounts()

        # Priority Grouping Architecture
        groups = [
            ("🚀 PRIMARY WORKHORSES (Priority 1 — Permanent High Durability)", [a for a in accounts if a.get("priority", 1) == 1]),
            ("⚡ SECONDARY CLOUD POOL (Priority 2 — Secondary Gmail Pool)", [a for a in accounts if a.get("priority", 1) == 2]),
            ("⏳ EXPIRING / TEMPORARY POOL (Priority 3 — Expiring Remotes)", [a for a in accounts if a.get("priority", 1) == 3]),
            ("🚨 OVERFLOW / LAST RESORT (Priority 99 — 5TB Emergency)", [a for a in accounts if a.get("priority", 1) >= 90]),
            ("📦 OTHER REGISTERED REMOTES", [a for a in accounts if a.get("priority", 1) not in (1, 2, 3) and a.get("priority", 1) < 90])
        ]

        for group_title, acc_list in groups:
            if not acc_list:
                continue

            # Insert distinct section header row
            self.accounts_tree.insert(
                "",
                tk.END,
                values=(
                    group_title,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    f"{len(acc_list)} Remote(s)"
                ),
                tags=("group_header",)
            )

            for a in acc_list:
                p = a.get("priority", 1)
                p_label = f"  • Priority {p}"

                usable = a["usable_capacity_bytes"]
                used = a["used_bytes"]
                free = max(0, usable - used)
                util_pct = (used / usable * 100.0) if usable > 0 else 0.0

                # Pre-flight ping & Rclone config validation
                acc_name = a["account_name"]
                in_rclone = self.db.is_remote_in_rclone_config(acc_name)
                acc_status = a.get("status", "CONNECTED")

                if acc_status == "DISCONNECTED":
                    chunks_held = self.db.get_account_chunks_count(acc_name)["count"]
                    status_str = f"⚪ Disconnected ({chunks_held} chunks preserved)" if chunks_held > 0 else "⚪ Disconnected (No data)"
                elif not in_rclone:
                    status_str = "🔴 Missing in rclone.conf (Offline)"
                elif util_pct >= 99.0:
                    status_str = f"🔴 Full / Limit Hit ({util_pct:.1f}%)"
                elif util_pct >= 90.0:
                    status_str = f"🟡 Nearing Limit ({util_pct:.1f}%)"
                else:
                    health = self.remote_health_map.get(acc_name)
                    if health:
                        if health["status"] == "green":
                            status_str = f"🟢 Online & Verified ({util_pct:.1f}% used)"
                        elif health["status"] == "yellow":
                            status_str = f"🟡 {health['msg']}"
                        else:
                            status_str = f"🔴 {health['msg']}"
                    else:
                        status_str = f"🟢 Ready ({util_pct:.1f}% used)"

                self.accounts_tree.insert(
                    "",
                    tk.END,
                    values=(
                        p_label,
                        a["account_name"],
                        a["provider"],
                        a["reliability_tier"],
                        format_bytes(usable),
                        format_bytes(used),
                        format_bytes(free),
                        status_str
                    )
                )

        # Refresh un-registered remotes dropdown in manual registration card
        if hasattr(self, "acc_name_combo"):
            unreg = self.db.get_unregistered_rclone_remotes()
            self.acc_name_combo["values"] = unreg
            if unreg:
                if self.acc_name_combo.get() not in unreg:
                    self.acc_name_combo.set(unreg[0])
            else:
                self.acc_name_combo.set("")

    def _on_sync_rclone(self):
        pruned = self.db.prune_ghost_remotes()
        if pruned:
            self.log(f"[CLEANUP] Pruned {len(pruned)} accidental / ghost remote(s): {', '.join(pruned)}")
        added = self.db.sync_from_rclone_config()
        self.refresh_all_data()
        if added > 0:
            self.log(f"[SYNC] Detected and registered {added} new remote(s) from rclone.conf.")
            messagebox.showinfo("Rclone Synced", f"Successfully synced {added} new remote(s) from rclone.conf!")
        else:
            self.log("[SYNC] Rclone config checked: all remotes are already registered.")
            messagebox.showinfo("Rclone Synced", "All remotes in rclone.conf are already registered in CloudPool.")

    def _on_unregister_account(self):
        """Removes an empty cloud remote from CloudPool or safely disconnects it if it contains chunks."""
        selected = self.accounts_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a cloud remote from the table.")
            return

        item = self.accounts_tree.item(selected[0])
        if "group_header" in item.get("tags", []):
            return

        acc_name = item["values"][1]
        if not acc_name:
            return

        # 1. Trace all references to this account in the database
        refs = self.db.get_account_references(acc_name)
        chunks_count = refs["chunks_count"]
        chunks_bytes = refs["chunks_bytes"]
        file_count = refs["file_count"]
        file_names_preview = ", ".join(refs["file_names"][:3])
        if len(refs["file_names"]) > 3:
            file_names_preview += f" and {len(refs['file_names']) - 3} other(s)"

        # Check if the account is already disconnected
        cur_acc = next((a for a in self.db.get_accounts() if a["account_name"] == acc_name), None)
        is_disconnected = (cur_acc and cur_acc.get("status") == "DISCONNECTED")

        # 2. Case A: Account contains stored chunks -> DO NOT allow destructive deletion!
        if chunks_count > 0:
            if is_disconnected:
                messagebox.showinfo(
                    "Remote Already Disconnected",
                    f"Remote '{acc_name}' is currently safely disconnected.\n\n"
                    f"• Preserves {chunks_count} chunk(s) ({format_bytes(chunks_bytes)}) across {file_count} file(s).\n"
                    f"• Stored data: {file_names_preview or 'N/A'}\n"
                    f"• Destructive deletion is blocked to prevent data loss.\n\n"
                    f"To restore active upload routing to this remote, click 'Reconnect Remote' or run Auto-Sync.",
                    parent=self.root
                )
                return

            # Offer Safe Disconnect Option
            prompt_msg = (
                f"Destructive Unregistration Blocked:\n"
                f"Remote '{acc_name}' cannot be deleted because it currently stores "
                f"{chunks_count} encrypted chunk(s) ({format_bytes(chunks_bytes)}) belonging to {file_count} virtual file(s)!\n\n"
                f"Referenced Files: {file_names_preview or 'Active Vault Chunks'}\n\n"
                f"Permanently removing this account would break file integrity and cause data loss.\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"Safe Alternative: Disconnect Remote\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"Would you like to safely DISCONNECT '{acc_name}' instead?\n\n"
                f"• The remote will be excluded from new chunk uploads.\n"
                f"• All existing chunk metadata and encryption keys remain safely preserved.\n"
                f"• Reconnecting the same account at any time will instantly restore full access.\n"
                f"• No remote files will be deleted.\n\n"
                f"Safely disconnect '{acc_name}' now?"
            )
            confirm_disconnect = messagebox.askyesno(
                "Remote Contains Stored Data — Disconnect Instead?",
                prompt_msg,
                parent=self.root
            )
            if confirm_disconnect:
                try:
                    self.db.disconnect_account(acc_name)
                    self.log(f"[ACCOUNT DISCONNECTED] '{acc_name}' safely disconnected. {chunks_count} chunks preserved.")
                    self.refresh_all_data()
                    messagebox.showinfo(
                        "Remote Disconnected",
                        f"Remote '{acc_name}' has been safely disconnected.\n\n"
                        f"• {chunks_count} chunk(s) remain safely mapped in your vault.\n"
                        f"• Reconnect this remote at any time to resume uploads.",
                        parent=self.root
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to disconnect remote:\n{e}", parent=self.root)
            return

        # 3. Case B: Account contains NO chunks -> Allow normal unregistration
        confirm = messagebox.askyesno(
            "Confirm Remote Removal",
            f"Are you sure you want to permanently unregister remote '{acc_name}' from CloudPool?\n\n"
            f"• Verified: This remote stores 0 data chunks.\n"
            f"• It will be removed from your cloud pool storage table.",
            parent=self.root
        )
        if not confirm:
            return

        try:
            self.db.unregister_account(acc_name)
            self.log(f"[ACCOUNT REMOVED] Successfully unregistered remote '{acc_name}'.")
            self.refresh_all_data()
            messagebox.showinfo("Remote Removed", f"Remote '{acc_name}' has been successfully removed from CloudPool.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Unregister Error", f"Failed to unregister remote:\n\n{e}", parent=self.root)

    def _on_reconnect_account(self):
        """Re-enables a disconnected cloud remote so it can participate in chunk routing again."""
        selected = self.accounts_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a disconnected cloud remote from the table to reconnect.")
            return

        item = self.accounts_tree.item(selected[0])
        if "group_header" in item.get("tags", []):
            return

        acc_name = item["values"][1]
        if not acc_name:
            return

        cur_acc = next((a for a in self.db.get_accounts() if a["account_name"] == acc_name), None)
        if not cur_acc:
            messagebox.showerror("Not Found", f"Remote '{acc_name}' is not found in database.")
            return

        if cur_acc.get("status") == "CONNECTED":
            messagebox.showinfo("Already Connected", f"Remote '{acc_name}' is already connected and active.")
            return

        try:
            self.db.reconnect_account(acc_name)
            self.log(f"[ACCOUNT RECONNECTED] '{acc_name}' restored to active status.")
            self.refresh_all_data()
            messagebox.showinfo(
                "Remote Reconnected",
                f"Remote '{acc_name}' has been successfully reconnected!\n\n"
                f"It is now active and ready to receive upload chunks.",
                parent=self.root
            )
        except Exception as e:
            messagebox.showerror("Reconnect Error", f"Failed to reconnect remote:\n\n{e}", parent=self.root)

    def _on_test_connectivity(self):
        """Probes all registered remotes in a background worker and reports their status."""
        if self.is_busy:
            messagebox.showwarning("Busy", "A transfer operation is currently running.")
            return

        accounts = self.db.get_accounts()
        if not accounts:
            messagebox.showinfo("No Accounts", "No accounts registered to test.")
            return

        self.log("[HEALTH CHECK] Probing connectivity for all registered cloud remotes...")

        def check_worker():
            results = []
            for a in accounts:
                name = a["account_name"]
                if not self.db.is_remote_in_rclone_config(name):
                    results.append((name, False, "Not found in rclone.conf (Missing section)"))
                    continue
                cmd = [RCLONE_BIN, "lsd", f"{name}:", "--max-depth", "1"]
                try:
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                    if res.returncode == 0:
                        results.append((name, True, "Connected & Operational"))
                    else:
                        err = res.stderr.strip().split("\n")[-1][:70] or "Failed to connect"
                        results.append((name, False, err))
                except Exception as ex:
                    results.append((name, False, str(ex)[:70]))

            lines = []
            all_good = True
            for name, ok, msg in results:
                icon = "🟢" if ok else "🔴"
                if not ok:
                    all_good = False
                lines.append(f"{icon} {name}: {msg}")

            report = "\n".join(lines)
            self.msg_queue.put({
                "type": "log",
                "msg": f"Health Check Results:\n{report}"
            })
            self.msg_queue.put({
                "type": "health_check_complete",
                "all_good": all_good,
                "report": report
            })

        threading.Thread(target=check_worker, daemon=True).start()

    def _on_provider_selected(self, event=None):
        provider = self.provider_combo.get()
        if provider == "Google Drive":
            self.raw_gb_entry.delete(0, tk.END); self.raw_gb_entry.insert(0, "15.0")
            self.buffer_gb_entry.delete(0, tk.END); self.buffer_gb_entry.insert(0, "0.5")
            self.priority_entry.delete(0, tk.END); self.priority_entry.insert(0, "2")
        elif provider == "MEGA":
            self.raw_gb_entry.delete(0, tk.END); self.raw_gb_entry.insert(0, "20.0")
            self.buffer_gb_entry.delete(0, tk.END); self.buffer_gb_entry.insert(0, "0.0")
            self.priority_entry.delete(0, tk.END); self.priority_entry.insert(0, "1")
        elif provider == "OneDrive":
            self.raw_gb_entry.delete(0, tk.END); self.raw_gb_entry.insert(0, "5.0")
            self.buffer_gb_entry.delete(0, tk.END); self.buffer_gb_entry.insert(0, "0.0")
            self.priority_entry.delete(0, tk.END); self.priority_entry.insert(0, "1")

    def _on_register_account(self):
        acc_name = self.acc_name_combo.get().strip()
        provider = self.provider_combo.get().strip()
        tier = self.acc_tier_combo.get().strip()

        if not acc_name:
            messagebox.showerror("Missing Remote Name", "Please select or type an Rclone remote name.")
            return

        # STRICT VALIDATION: Ensure remote actually exists in rclone.conf
        if not self.db.is_remote_in_rclone_config(acc_name):
            messagebox.showerror(
                "Remote Not Found in Rclone",
                f"Cannot register '{acc_name}':\n\n"
                f"This remote does NOT exist in your Rclone configuration (%APPDATA%\\rclone\\rclone.conf).\n\n"
                f"Please configure '{acc_name}' first using Rclone or the OAuth setup script before registering it in CloudPool."
            )
            return

        try:
            raw_gb = float(self.raw_gb_entry.get().strip())
            buffer_gb = float(self.buffer_gb_entry.get().strip())
            priority = int(self.priority_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Raw GB, Buffer GB, and Priority must be valid numeric values.")
            return

        if raw_gb <= buffer_gb:
            messagebox.showerror("Invalid Capacity", "Raw capacity must be greater than the reserved buffer.")
            return

        self.db.register_account(acc_name, provider, raw_gb, buffer_gb, tier, priority=priority)
        self.log(f"Registered cloud remote '{acc_name}' ({provider}, {raw_gb}GB, P{priority}, {tier})")
        self.refresh_all_data()
        messagebox.showinfo("Remote Registered", f"Account '{acc_name}' registered successfully with Priority {priority}!")


def main():
    if HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    app = CloudPoolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
