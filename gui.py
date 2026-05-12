"""CustomTkinter GUI for RSA-OAEP-256 encrypt/decrypt/keygen."""

import os
import threading
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox

import customtkinter as ctk

from rsa_core import gen_keypair
from rsa_oaep import (
    KEY_BITS,
    decrypt_file,
    encrypt_file,
    load_key,
    save_private_key,
    save_public_key,
)


ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

ACCENT = "#4C2A85"
ACCENT_HOVER = "#3A1E68"
ACCENT_SOFT = "#6A45A5"
ACCENT_SOFT_HOVER = "#5A3897"
TEXT_DARK = "#1F1B3A"
TEXT_MUTED = "#6B6785"
BORDER = "#E1DCF0"
ENTRY_BG = "#FCFBFF"
ENTRY_PLACEHOLDER = "#8F8F99"
APP_BG = "#F6F4FB"
RIGHT_BG = "#F3EEFF"
LEFT_FALLBACK = ACCENT


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RSA-OAEP-256 Tool")
        self.geometry("1180x720")
        self.minsize(980, 620)
        self.configure(fg_color=APP_BG)

        self.font_family = self._pick_font_family()
        self._apply_global_fonts()
        self._setup_hero_fonts()
        self._hero_image = self._load_background_image()

        self.grid_columnconfigure(0, weight=11)
        self.grid_columnconfigure(1, weight=14)
        self.grid_rowconfigure(0, weight=1)

        self.left_panel = ctk.CTkFrame(self, corner_radius=0, fg_color=LEFT_FALLBACK)
        self.left_panel.grid(row=0, column=0, sticky="nsew")
        self.left_panel.grid_rowconfigure(0, weight=1)
        self.left_panel.grid_columnconfigure(0, weight=1)

        self.right_panel = ctk.CTkFrame(self, corner_radius=0, fg_color=RIGHT_BG)
        self.right_panel.grid(row=0, column=1, sticky="nsew")
        self.right_panel.grid_rowconfigure(1, weight=1)
        self.right_panel.grid_columnconfigure(0, weight=1)

        self._build_left_panel()
        self._build_right_panel()
        self.after(120, self._draw_hero)

    # --------------------------- layout helpers ---------------------------

    def _pick_font_family(self) -> str:
        family_names = list(tkfont.families())
        family_map = {name.lower(): name for name in family_names}
        exact_candidates = [
            "poppins medium",
            "poppins",
            "poppins regular",
            "poppins semi bold",
            "poppins semibold",
        ]
        for candidate in exact_candidates:
            if candidate in family_map:
                return family_map[candidate]
        for name in family_names:
            if "poppins" in name.lower():
                return name
        return "Poppins"

    def _apply_global_fonts(self):
        self.option_add("*Font", f"{{{self.font_family}}} 12")
        for font_name in (
            "TkDefaultFont",
            "TkTextFont",
            "TkMenuFont",
            "TkHeadingFont",
            "TkCaptionFont",
            "TkSmallCaptionFont",
            "TkIconFont",
            "TkTooltipFont",
            "TkFixedFont",
        ):
            try:
                named_font = tkfont.nametofont(font_name)
                named_font.configure(
                    family=self.font_family,
                    underline=False,
                    overstrike=False,
                )
            except tk.TclError:
                continue

    def _setup_hero_fonts(self):
        self.hero_title_font = tkfont.Font(
            family=self.font_family,
            size=27,
            weight="bold",
            underline=False,
        )
        self.hero_body_font = tkfont.Font(
            family=self.font_family,
            size=15,
            weight="normal",
            underline=False,
        )
        self.hero_list_font = tkfont.Font(
            family=self.font_family,
            size=16,
            weight="bold",
            underline=False,
        )
        self.hero_note_font = tkfont.Font(
            family=self.font_family,
            size=13,
            weight="normal",
            underline=False,
        )

    def _font(self, size: int, weight: str = "normal"):
        return ctk.CTkFont(family=self.font_family, size=size, weight=weight)

    def _load_background_image(self):
        image_path = os.path.join(os.path.dirname(__file__), "background.jpg")
        if not os.path.exists(image_path):
            return None
        try:
            return tk.PhotoImage(file=image_path, format="gif -index 0")
        except tk.TclError:
            try:
                return tk.PhotoImage(file=image_path)
            except tk.TclError:
                return None

    def _build_left_panel(self):
        self.hero_canvas = tk.Canvas(
            self.left_panel,
            highlightthickness=0,
            bd=0,
            bg=LEFT_FALLBACK,
        )
        self.hero_canvas.grid(row=0, column=0, sticky="nsew")
        self.hero_canvas.bind("<Configure>", lambda _event: self._draw_hero())

    def _draw_hero(self):
        canvas = self.hero_canvas
        width = max(canvas.winfo_width(), 420)
        height = max(canvas.winfo_height(), 620)
        canvas.delete("all")

        if self._hero_image is not None:
            canvas.create_image(width // 2, height // 2, image=self._hero_image)
        else:
            canvas.create_rectangle(0, 0, width, height, fill=LEFT_FALLBACK, outline="")

        canvas.create_text(
            42,
            102,
            anchor="nw",
            text="Selamat Datang!",
            fill="#FFFFFF",
            font=self.hero_title_font,
            width=max(width - 84, 260),
        )
        canvas.create_line(42, 186, 370, 186, fill="#FFFFFF", width=5)
        canvas.create_text(
            42,
            222,
            anchor="nw",
            text=(
                "Aplikasi ini membantu membuat kunci RSA 2048-bit, "
                "mengenkripsi file, dan mengembalikan plaintext asli "
                "dengan skema RSA-OAEP-256."
            ),
            fill="#F7F4FF",
            font=self.hero_body_font,
            width=max(width - 94, 250),
        )
        canvas.create_text(
            42,
            390,
            anchor="nw",
            text=(
                "Dibuat oleh:\n"
                "• Gilbert Kristian (2306274951)\n"
                "• Husin Hidayatul Hakim (2306152481)\n"
                "• Ivan Jehuda Angi (2306152222)"
            ),
            fill="#F7F4FF",
            font=self.hero_body_font,
            width=max(width - 94, 250),
        )
        canvas.create_text(
            42,
            height - 70,
            anchor="w",
            text="Proses dapat memerlukan beberapa detik untuk perhitungan panjang.",
            fill="#F1EEFF",
            font=self.hero_note_font,
            width=max(width - 94, 250),
        )

    def _build_right_panel(self):
        ctk.CTkLabel(
            self.right_panel,
            text="Pilih proses yang dibutuhkan, lalu isi file input, key hex, dan output.",
            text_color=TEXT_MUTED,
            font=self._font(14),
        ).grid(row=0, column=0, sticky="w", padx=42, pady=(36, 18))

        card = ctk.CTkFrame(
            self.right_panel,
            corner_radius=28,
            fg_color="#FFFFFF",
            border_width=1,
            border_color=BORDER,
        )
        card.grid(row=1, column=0, sticky="nsew", padx=36, pady=(0, 34))
        card.grid_rowconfigure(0, weight=1)
        card.grid_columnconfigure(0, weight=1)

        self.tabs = ctk.CTkTabview(
            card,
            fg_color="#FFFFFF",
            segmented_button_fg_color=ACCENT_SOFT,
            segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_HOVER,
            segmented_button_unselected_color=ACCENT_SOFT,
            segmented_button_unselected_hover_color=ACCENT_SOFT_HOVER,
            text_color="#FFFFFF",
            text_color_disabled="#F4ECFF",
            corner_radius=22,
            border_width=0,
            anchor="n",
        )
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
        self.tabs._segmented_button.configure(font=self._font(13, "bold"))

        self.tabs.add("Generate Keys")
        self.tabs.add("Encrypt")
        self.tabs.add("Decrypt")

        gen_tab = self.tabs.tab("Generate Keys")
        gen_tab.configure(fg_color="#FFFFFF")
        self._build_genkey(self._make_scroll_tab(gen_tab))

        enc_tab = self.tabs.tab("Encrypt")
        enc_tab.configure(fg_color="#FFFFFF")
        self._build_encrypt(self._make_scroll_tab(enc_tab))

        dec_tab = self.tabs.tab("Decrypt")
        dec_tab.configure(fg_color="#FFFFFF")
        self._build_decrypt(self._make_scroll_tab(dec_tab))

    def _make_scroll_tab(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(
            parent,
            fg_color="#FFFFFF",
            corner_radius=0,
            scrollbar_button_color="#D4C7F8",
            scrollbar_button_hover_color="#B8A3F1",
        )
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, minsize=112)
        return frame

    def _build_section_title(
        self,
        parent,
        title: str,
        subtitle: str,
        *,
        title_pady=(16, 4),
        subtitle_pady=(0, 18),
    ):
        ctk.CTkLabel(
            parent,
            text=title,
            text_color=TEXT_DARK,
            font=self._font(22, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=title_pady)
        subtitle_label = ctk.CTkLabel(
            parent,
            text=subtitle,
            text_color=TEXT_MUTED,
            font=self._font(13),
            justify="left",
            anchor="w",
            wraplength=690,
        )
        subtitle_label.grid(row=1, column=0, columnspan=3, sticky="ew", padx=14, pady=subtitle_pady)
        self._bind_responsive_wrap(parent, subtitle_label)

    def _bind_responsive_wrap(self, parent, label):
        def update_wrap(event=None):
            width = parent.winfo_width()
            if event is not None and getattr(event, "width", 0):
                width = event.width
            label.configure(wraplength=max(width - 160, 220))

        parent.bind("<Configure>", update_wrap, add="+")
        self.after(0, update_wrap)

    def _file_row(
        self,
        parent,
        row,
        label_text,
        browse_cmd,
        placeholder,
        *,
        label_pady=(10, 6),
        entry_pady=(0, 8),
        entry_height=46,
        button_height=46,
    ):
        ctk.CTkLabel(
            parent,
            text=label_text,
            text_color=TEXT_DARK,
            font=self._font(13, "bold"),
            anchor="w",
        ).grid(row=row, column=0, sticky="w", padx=14, pady=label_pady)

        entry = ctk.CTkEntry(
            parent,
            height=entry_height,
            corner_radius=15,
            border_width=1,
            border_color=BORDER,
            fg_color=ENTRY_BG,
            text_color=ENTRY_PLACEHOLDER,
            placeholder_text="",
            placeholder_text_color=ENTRY_PLACEHOLDER,
            font=self._font(13),
        )
        entry.grid(
            row=row + 1,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=(14, 10),
            pady=entry_pady,
        )
        self._set_entry_value(entry, placeholder)
        entry.configure(state="readonly")
        entry.bind("<Key>", lambda _event: "break")
        entry.bind("<<Paste>>", lambda _event: "break")
        entry.bind("<<Cut>>", lambda _event: "break")
        entry.bind("<Control-v>", lambda _event: "break")
        entry.bind("<Control-x>", lambda _event: "break")
        entry.bind("<Button-1>", lambda _event: "break")
        entry.bind("<Double-Button-1>", lambda _event: "break")
        entry.bind("<Triple-Button-1>", lambda _event: "break")
        entry.bind("<Button-3>", lambda _event: "break")
        entry._placeholder_value = placeholder

        ctk.CTkButton(
            parent,
            text="Browse",
            width=112,
            height=button_height,
            corner_radius=15,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color="#FFFFFF",
            font=self._font(13, "bold"),
            command=lambda: browse_cmd(entry),
        ).grid(row=row + 1, column=2, sticky="ew", padx=(0, 14), pady=entry_pady)
        return entry

    def _primary_button(self, parent, text, command, *, height=48):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            height=height,
            corner_radius=24,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color="#FFFFFF",
            font=self._font(14, "bold"),
        )

    def _secondary_button(self, parent, text, command, *, height=48):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            height=height,
            corner_radius=24,
            fg_color="#FFFFFF",
            hover_color="#F1ECFB",
            border_width=1,
            border_color=BORDER,
            text_color=ACCENT,
            font=self._font(14, "bold"),
        )

    @staticmethod
    def _ask_open(entry):
        path = filedialog.askopenfilename()
        if path:
            App._set_entry_value(entry, path)

    @staticmethod
    def _ask_save(entry, default_name=""):
        path = filedialog.asksaveasfilename(initialfile=default_name)
        if path:
            App._set_entry_value(entry, path)

    @staticmethod
    def _ask_save_suggested(entry, suggested_path: str):
        initialdir = None
        initialfile = suggested_path
        if suggested_path:
            initialdir = os.path.dirname(suggested_path) or None
            initialfile = os.path.basename(suggested_path)
        options = {"initialfile": initialfile}
        if initialdir:
            options["initialdir"] = initialdir
        path = filedialog.asksaveasfilename(**options)
        if path:
            App._set_entry_value(entry, path)

    @staticmethod
    def _entry_real_value(entry):
        value = entry.get().strip()
        placeholder = getattr(entry, "_placeholder_value", "")
        if value == placeholder:
            return ""
        return value

    @staticmethod
    def _set_entry_value(entry, value: str):
        entry.configure(state="normal")
        entry.delete(0, "end")
        entry.insert(0, value)
        entry.configure(state="readonly")

    @staticmethod
    def _reset_entry(entry):
        App._set_entry_value(entry, getattr(entry, "_placeholder_value", ""))

    @staticmethod
    def _reset_entries(*entries):
        for entry in entries:
            App._reset_entry(entry)

    @staticmethod
    def _suggest_encrypted_path(path: str) -> str:
        folder = os.path.dirname(path)
        filename = os.path.basename(path)
        encrypted_name = f"enc_{filename}.enc"
        return os.path.join(folder, encrypted_name) if folder else encrypted_name

    @staticmethod
    def _suggest_decrypted_path(path: str) -> str:
        if path.lower().endswith(".enc"):
            plain_path = path[:-4]
            folder = os.path.dirname(plain_path)
            filename = os.path.basename(plain_path)
            if filename.startswith("enc_"):
                filename = filename[4:]
            base, ext = os.path.splitext(filename)
            decrypted_name = f"{base}.decrypted{ext}" if ext else f"{filename}.decrypted"
            return os.path.join(folder, decrypted_name) if folder else decrypted_name
        base, ext = os.path.splitext(path)
        return f"{base}.decrypted{ext}" if ext else f"{path}.decrypted"

    def _run_async(self, work, on_done=None):
        def runner():
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("Error", str(exc)))
                if on_done:
                    self.after(0, lambda: on_done(None, exc))
                return
            if on_done:
                self.after(0, lambda: on_done(result, None))

        threading.Thread(target=runner, daemon=True).start()

    # --------------------------- Generate Keys ---------------------------

    def _build_genkey(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)
        parent.grid_columnconfigure(2, minsize=112)

        self._build_section_title(
            parent,
            "Generate RSA keypair",
            "Gunakan tab ini untuk membuat public key dan private key 2048-bit dalam format hexadecimal.",
            title_pady=(10, 2),
            subtitle_pady=(0, 12),
        )

        self.gen_pub = self._file_row(
            parent,
            2,
            "Public key file",
            lambda entry: self._ask_save(entry, "public.key"),
            "Contoh: public.key",
            label_pady=(6, 4),
            entry_pady=(0, 6),
            entry_height=42,
            button_height=42,
        )
        self.gen_priv = self._file_row(
            parent,
            4,
            "Private key file",
            lambda entry: self._ask_save(entry, "private.key"),
            "Contoh: private.key",
            label_pady=(6, 4),
            entry_pady=(0, 6),
            entry_height=42,
            button_height=42,
        )

        self.gen_btn = self._primary_button(
            parent,
            f"Generate Keypair ({KEY_BITS}-bit)",
            self._on_gen,
            height=44,
        )
        self.gen_btn.grid(row=6, column=0, columnspan=2, padx=(14, 10), pady=(10, 8), sticky="ew")
        self.gen_reset_btn = self._secondary_button(
            parent,
            "Reset",
            self._reset_gen,
            height=44,
        )
        self.gen_reset_btn.grid(row=6, column=2, padx=(0, 14), pady=(10, 8), sticky="ew")

        self.gen_status = ctk.CTkLabel(
            parent,
            text="",
            text_color=TEXT_MUTED,
            font=self._font(13),
            anchor="w",
            justify="left",
            wraplength=690,
        )
        self.gen_status.grid(row=7, column=0, columnspan=3, padx=14, pady=(0, 8), sticky="ew")

    def _on_gen(self):
        pub_path = self._entry_real_value(self.gen_pub)
        priv_path = self._entry_real_value(self.gen_priv)
        if not pub_path or not priv_path:
            messagebox.showerror("Error", "Tentukan path file public key dan private key.")
            return

        self.gen_btn.configure(state="disabled")
        self.gen_status.configure(text="Membuat keypair baru. Ini bisa memerlukan beberapa detik.")

        def work():
            pub, priv = gen_keypair(KEY_BITS)
            save_public_key(pub_path, pub)
            save_private_key(priv_path, priv)
            return pub_path, priv_path

        def done(result, err):
            self.gen_btn.configure(state="normal")
            if err:
                self.gen_status.configure(text="Pembuatan keypair gagal.")
                return
            pub_p, priv_p = result
            self.gen_status.configure(
                text=(
                    "Keypair selesai disimpan: "
                    f"{os.path.basename(pub_p)} dan {os.path.basename(priv_p)}."
                )
            )

        self._run_async(work, done)

    def _reset_gen(self):
        self._reset_entries(self.gen_pub, self.gen_priv)
        self.gen_status.configure(text="")

    # --------------------------- Encrypt ---------------------------

    def _build_encrypt(self, parent):
        self._build_section_title(
            parent,
            "Encrypt file",
            "Masukkan file plaintext, public key heksadesimal, lalu pilih file output untuk ciphertext.",
        )

        self.enc_in = self._file_row(
            parent,
            2,
            "Plaintext file",
            self._ask_encrypt_input,
            "Pilih file input apa pun",
        )
        self.enc_key = self._file_row(
            parent,
            4,
            "Public key file",
            self._ask_open,
            "Pilih file key publik",
        )
        self.enc_out = self._file_row(
            parent,
            6,
            "Ciphertext output",
            self._ask_encrypt_output,
            "pilih plaintext dulu",
        )

        self.enc_btn = self._primary_button(parent, "Encrypt", self._on_encrypt)
        self.enc_btn.grid(row=8, column=0, columnspan=2, padx=(14, 10), pady=(18, 14), sticky="ew")
        self.enc_reset_btn = self._secondary_button(parent, "Reset", self._reset_encrypt)
        self.enc_reset_btn.grid(row=8, column=2, padx=(0, 14), pady=(18, 14), sticky="ew")

        self.enc_status = ctk.CTkLabel(
            parent,
            text="",
            text_color=TEXT_MUTED,
            font=self._font(13),
            anchor="w",
            justify="left",
            wraplength=690,
        )
        self.enc_status.grid(row=9, column=0, columnspan=3, padx=14, pady=(0, 8), sticky="ew")

    def _on_encrypt(self):
        in_path = self._entry_real_value(self.enc_in)
        key_path = self._entry_real_value(self.enc_key)
        out_path = self._entry_real_value(self.enc_out)
        if not (in_path and key_path and out_path):
            messagebox.showerror("Error", "Lengkapi pengisian semua file.")
            return
        if not os.path.isfile(in_path):
            messagebox.showerror("Error", f"File plaintext tidak ditemukan: {in_path}")
            return
        if not os.path.isfile(key_path):
            messagebox.showerror("Error", f"File key tidak ditemukan: {key_path}")
            return

        try:
            pub = load_key(key_path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Error", f"Gagal membaca public key: {exc}")
            return

        self.enc_btn.configure(state="disabled")
        self.enc_status.configure(text="Enkripsi sedang berjalan.")

        def progress(done, total):
            self.after(
                0,
                lambda: self.enc_status.configure(
                    text=f"Enkripsi blok {done} dari {total} sedang diproses."
                ),
            )

        def work():
            encrypt_file(in_path, out_path, pub, progress_cb=progress)
            return os.path.getsize(out_path)

        def done(result, err):
            self.enc_btn.configure(state="normal")
            if err:
                self.enc_status.configure(text="Enkripsi gagal.")
                return
            self.enc_status.configure(
                text=f"Enkripsi selesai. Ciphertext tersimpan ({result} byte)."
            )

        self._run_async(work, done)

    def _reset_encrypt(self):
        self._reset_entries(self.enc_in, self.enc_key, self.enc_out)
        self.enc_status.configure(text="")

    def _ask_encrypt_input(self, entry):
        path = filedialog.askopenfilename()
        if not path:
            return
        self._set_entry_value(entry, path)
        if not self._entry_real_value(self.enc_out):
            self._set_entry_value(self.enc_out, self._suggest_encrypted_path(path))

    def _ask_encrypt_output(self, entry):
        in_path = self._entry_real_value(self.enc_in)
        suggested = self._suggest_encrypted_path(in_path) if in_path else "ciphertext.enc"
        self._ask_save_suggested(entry, suggested)

    # --------------------------- Decrypt ---------------------------

    def _build_decrypt(self, parent):
        self._build_section_title(
            parent,
            "Decrypt file",
            "Masukkan ciphertext dan private key, lalu simpan hasil plaintext ke file output.",
        )

        self.dec_in = self._file_row(
            parent,
            2,
            "Ciphertext file",
            self._ask_decrypt_input,
            "Pilih file ciphertext",
        )
        self.dec_key = self._file_row(
            parent,
            4,
            "Private key file",
            self._ask_open,
            "Pilih file key privat",
        )
        self.dec_out = self._file_row(
            parent,
            6,
            "Plaintext output",
            self._ask_decrypt_output,
            "pilih ciphertext dulu",
        )

        self.dec_btn = self._primary_button(parent, "Decrypt", self._on_decrypt)
        self.dec_btn.grid(row=8, column=0, columnspan=2, padx=(14, 10), pady=(18, 14), sticky="ew")
        self.dec_reset_btn = self._secondary_button(parent, "Reset", self._reset_decrypt)
        self.dec_reset_btn.grid(row=8, column=2, padx=(0, 14), pady=(18, 14), sticky="ew")

        self.dec_status = ctk.CTkLabel(
            parent,
            text="",
            text_color=TEXT_MUTED,
            font=self._font(13),
            anchor="w",
            justify="left",
            wraplength=690,
        )
        self.dec_status.grid(row=9, column=0, columnspan=3, padx=14, pady=(0, 8), sticky="ew")

    def _on_decrypt(self):
        in_path = self._entry_real_value(self.dec_in)
        key_path = self._entry_real_value(self.dec_key)
        out_path = self._entry_real_value(self.dec_out)
        if not (in_path and key_path and out_path):
            messagebox.showerror("Error", "Lengkapi pengisian semua file.")
            return
        if not os.path.isfile(in_path):
            messagebox.showerror("Error", f"File ciphertext tidak ditemukan: {in_path}")
            return
        if not os.path.isfile(key_path):
            messagebox.showerror("Error", f"File key tidak ditemukan: {key_path}")
            return

        try:
            priv = load_key(key_path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Error", f"Gagal membaca private key: {exc}")
            return

        self.dec_btn.configure(state="disabled")
        self.dec_status.configure(text="Dekripsi sedang berjalan.")

        def progress(done, total):
            self.after(
                0,
                lambda: self.dec_status.configure(
                    text=f"Dekripsi blok {done} dari {total} sedang diproses."
                ),
            )

        def work():
            decrypt_file(in_path, out_path, priv, progress_cb=progress)
            return os.path.getsize(out_path)

        def done(result, err):
            self.dec_btn.configure(state="normal")
            if err:
                self.dec_status.configure(text="Dekripsi gagal.")
                return
            self.dec_status.configure(
                text=f"Dekripsi selesai. Plaintext tersimpan ({result} byte)."
            )

        self._run_async(work, done)

    def _reset_decrypt(self):
        self._reset_entries(self.dec_in, self.dec_key, self.dec_out)
        self.dec_status.configure(text="")

    def _ask_decrypt_input(self, entry):
        path = filedialog.askopenfilename()
        if not path:
            return
        self._set_entry_value(entry, path)
        if not self._entry_real_value(self.dec_out):
            self._set_entry_value(self.dec_out, self._suggest_decrypted_path(path))

    def _ask_decrypt_output(self, entry):
        in_path = self._entry_real_value(self.dec_in)
        suggested = self._suggest_decrypted_path(in_path) if in_path else "plaintext.decrypted"
        self._ask_save_suggested(entry, suggested)
