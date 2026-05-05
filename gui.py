"""CustomTkinter GUI for RSA-OAEP-256 encrypt/decrypt/keygen."""

import os
import threading
from tkinter import filedialog, messagebox

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


ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RSA-OAEP-256 Tool")
        self.geometry("760x520")
        self.minsize(680, 480)

        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=12)
        self.tabs.add("Generate Keys")
        self.tabs.add("Encrypt")
        self.tabs.add("Decrypt")

        self._build_genkey(self.tabs.tab("Generate Keys"))
        self._build_encrypt(self.tabs.tab("Encrypt"))
        self._build_decrypt(self.tabs.tab("Decrypt"))

    # --------------------------- helpers ---------------------------

    @staticmethod
    def _file_row(parent, row, label_text, browse_cmd):
        ctk.CTkLabel(parent, text=label_text, anchor="w").grid(
            row=row, column=0, sticky="w", padx=10, pady=6
        )
        entry = ctk.CTkEntry(parent)
        entry.grid(row=row, column=1, sticky="ew", padx=5, pady=6)
        ctk.CTkButton(
            parent, text="Browse", width=90, command=lambda: browse_cmd(entry)
        ).grid(row=row, column=2, padx=5, pady=6)
        return entry

    @staticmethod
    def _ask_open(entry):
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    @staticmethod
    def _ask_save(entry, default_name=""):
        path = filedialog.asksaveasfilename(initialfile=default_name)
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _run_async(self, work, on_done=None):
        def runner():
            try:
                result = work()
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                if on_done:
                    self.after(0, lambda: on_done(None, e))
                return
            if on_done:
                self.after(0, lambda: on_done(result, None))

        threading.Thread(target=runner, daemon=True).start()

    # --------------------------- Generate Keys ---------------------------

    def _build_genkey(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.gen_pub = self._file_row(
            parent, 0, "Public key file:",
            lambda e: self._ask_save(e, "public.key"),
        )
        self.gen_priv = self._file_row(
            parent, 1, "Private key file:",
            lambda e: self._ask_save(e, "private.key"),
        )

        self.gen_btn = ctk.CTkButton(
            parent, text=f"Generate Keypair ({KEY_BITS}-bit)",
            command=self._on_gen, height=38,
        )
        self.gen_btn.grid(row=2, column=0, columnspan=3, padx=10, pady=18, sticky="ew")

        self.gen_progress = ctk.CTkProgressBar(parent, mode="indeterminate")
        self.gen_progress.grid(row=3, column=0, columnspan=3, padx=10, pady=4, sticky="ew")
        self.gen_progress.set(0)

        self.gen_status = ctk.CTkLabel(parent, text="Idle.", anchor="w")
        self.gen_status.grid(row=4, column=0, columnspan=3, padx=10, pady=6, sticky="ew")

        info = (
            "Membangkitkan dua bilangan prima 1024-bit (Miller-Rabin),\n"
            "lalu menghitung n = p*q, e = 65537, d = e^-1 mod lambda(n).\n"
            "Proses ini biasanya memerlukan beberapa detik."
        )
        ctk.CTkLabel(parent, text=info, justify="left", anchor="w").grid(
            row=5, column=0, columnspan=3, padx=10, pady=10, sticky="w"
        )

    def _on_gen(self):
        pub_path = self.gen_pub.get().strip()
        priv_path = self.gen_priv.get().strip()
        if not pub_path or not priv_path:
            messagebox.showerror("Error", "Tentukan path file public dan private key.")
            return

        self.gen_btn.configure(state="disabled")
        self.gen_status.configure(text="Generating prime numbers...")
        self.gen_progress.start()

        def work():
            pub, priv = gen_keypair(KEY_BITS)
            save_public_key(pub_path, pub)
            save_private_key(priv_path, priv)
            return pub_path, priv_path

        def done(result, err):
            self.gen_progress.stop()
            self.gen_progress.set(0)
            self.gen_btn.configure(state="normal")
            if err:
                self.gen_status.configure(text="Failed.")
            else:
                pub_p, priv_p = result
                self.gen_status.configure(
                    text=f"OK. Saved {os.path.basename(pub_p)} & {os.path.basename(priv_p)}"
                )

        self._run_async(work, done)

    # --------------------------- Encrypt ---------------------------

    def _build_encrypt(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.enc_in = self._file_row(parent, 0, "Plaintext file:", self._ask_open)
        self.enc_key = self._file_row(parent, 1, "Public key file:", self._ask_open)
        self.enc_out = self._file_row(
            parent, 2, "Ciphertext output:",
            lambda e: self._ask_save(e, "ciphertext.bin"),
        )

        self.enc_btn = ctk.CTkButton(
            parent, text="Encrypt", command=self._on_encrypt, height=38,
        )
        self.enc_btn.grid(row=3, column=0, columnspan=3, padx=10, pady=18, sticky="ew")

        self.enc_progress = ctk.CTkProgressBar(parent)
        self.enc_progress.grid(row=4, column=0, columnspan=3, padx=10, pady=4, sticky="ew")
        self.enc_progress.set(0)

        self.enc_status = ctk.CTkLabel(parent, text="Idle.", anchor="w")
        self.enc_status.grid(row=5, column=0, columnspan=3, padx=10, pady=6, sticky="ew")

    def _on_encrypt(self):
        in_path = self.enc_in.get().strip()
        key_path = self.enc_key.get().strip()
        out_path = self.enc_out.get().strip()
        if not (in_path and key_path and out_path):
            messagebox.showerror("Error", "Lengkapi semua path file.")
            return
        if not os.path.isfile(in_path):
            messagebox.showerror("Error", f"File plaintext tidak ditemukan: {in_path}")
            return
        if not os.path.isfile(key_path):
            messagebox.showerror("Error", f"File key tidak ditemukan: {key_path}")
            return

        try:
            pub = load_key(key_path)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Error", f"Gagal membaca public key: {e}")
            return

        self.enc_btn.configure(state="disabled")
        self.enc_progress.set(0)
        self.enc_status.configure(text="Encrypting...")

        def progress(done, total):
            frac = done / total if total else 1.0
            self.after(0, lambda: self.enc_progress.set(frac))
            self.after(0, lambda: self.enc_status.configure(
                text=f"Encrypting block {done}/{total}..."
            ))

        def work():
            encrypt_file(in_path, out_path, pub, progress_cb=progress)
            return os.path.getsize(out_path)

        def done(result, err):
            self.enc_btn.configure(state="normal")
            if err:
                self.enc_status.configure(text="Failed.")
                self.enc_progress.set(0)
            else:
                self.enc_progress.set(1.0)
                self.enc_status.configure(
                    text=f"Done. Ciphertext written ({result} bytes) -> {out_path}"
                )

        self._run_async(work, done)

    # --------------------------- Decrypt ---------------------------

    def _build_decrypt(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.dec_in = self._file_row(parent, 0, "Ciphertext file:", self._ask_open)
        self.dec_key = self._file_row(parent, 1, "Private key file:", self._ask_open)
        self.dec_out = self._file_row(
            parent, 2, "Plaintext output:",
            lambda e: self._ask_save(e, "plaintext.bin"),
        )

        self.dec_btn = ctk.CTkButton(
            parent, text="Decrypt", command=self._on_decrypt, height=38,
        )
        self.dec_btn.grid(row=3, column=0, columnspan=3, padx=10, pady=18, sticky="ew")

        self.dec_progress = ctk.CTkProgressBar(parent)
        self.dec_progress.grid(row=4, column=0, columnspan=3, padx=10, pady=4, sticky="ew")
        self.dec_progress.set(0)

        self.dec_status = ctk.CTkLabel(parent, text="Idle.", anchor="w")
        self.dec_status.grid(row=5, column=0, columnspan=3, padx=10, pady=6, sticky="ew")

    def _on_decrypt(self):
        in_path = self.dec_in.get().strip()
        key_path = self.dec_key.get().strip()
        out_path = self.dec_out.get().strip()
        if not (in_path and key_path and out_path):
            messagebox.showerror("Error", "Lengkapi semua path file.")
            return
        if not os.path.isfile(in_path):
            messagebox.showerror("Error", f"File ciphertext tidak ditemukan: {in_path}")
            return
        if not os.path.isfile(key_path):
            messagebox.showerror("Error", f"File key tidak ditemukan: {key_path}")
            return

        try:
            priv = load_key(key_path)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Error", f"Gagal membaca private key: {e}")
            return

        self.dec_btn.configure(state="disabled")
        self.dec_progress.set(0)
        self.dec_status.configure(text="Decrypting...")

        def progress(done, total):
            frac = done / total if total else 1.0
            self.after(0, lambda: self.dec_progress.set(frac))
            self.after(0, lambda: self.dec_status.configure(
                text=f"Decrypting block {done}/{total}..."
            ))

        def work():
            decrypt_file(in_path, out_path, priv, progress_cb=progress)
            return os.path.getsize(out_path)

        def done(result, err):
            self.dec_btn.configure(state="normal")
            if err:
                self.dec_status.configure(text="Failed.")
                self.dec_progress.set(0)
            else:
                self.dec_progress.set(1.0)
                self.dec_status.configure(
                    text=f"Done. Plaintext written ({result} bytes) -> {out_path}"
                )

        self._run_async(work, done)
