import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from transformers import AutoTokenizer, AutoModelForCausalLM
from fpdf import FPDF
import os
import re

# Load the model and tokenizer
try:
    tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3.2-1B")
    model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3.2-1B")
except Exception as e:
    print("Error loading model:", e)
    exit("Ensure the model and tokenizer are correctly installed.")

# Detect placeholders dynamically
def detect_placeholders(template):
    return [match.group(1) for match in re.finditer(r"\{(.*?)\}", template)]

# Generate text
def generate_text_with_transformers(prompt, max_length=500):
    inputs = tokenizer(prompt, return_tensors="pt")
    outputs = model.generate(
        **inputs, max_length=max_length, temperature=0.7, top_p=0.9, num_return_sequences=1
    )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)

# Save to PDF
def save_to_pdf(content, output_pdf_path):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, content)
    pdf.output(output_pdf_path)

# Form Application
class FormApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Form Filling Application")
        self.root.geometry("600x700")

        self.forms = {
            "Affidavit": "prompt.txt",
            "Birth Registration": "birth.txt",
            "Death Registration": "death.txt",
        }

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Form Filling Application", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Select a Form:", font=("Arial", 12)).pack(pady=5)
        self.form_var = tk.StringVar()
        self.form_dropdown = ttk.Combobox(self.root, textvariable=self.form_var, state="readonly")
        self.form_dropdown["values"] = list(self.forms.keys())
        self.form_dropdown.pack(pady=5)
        self.form_dropdown.bind("<<ComboboxSelected>>", self.load_form_template)

        # Scrollable Frame
        self.canvas = tk.Canvas(self.root, width=580)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.generate_button = tk.Button(self.root, text="Generate Form", command=self.generate_form)
        self.generate_button.pack(pady=20)

        self.placeholder_vars = {}

    def load_form_template(self, event):
        selected_form = self.form_var.get()
        prompt_file_path = self.forms[selected_form]

        if not os.path.exists(prompt_file_path):
            messagebox.showerror("Error", f"Template file '{prompt_file_path}' not found!")
            return

        with open(prompt_file_path, "r") as file:
            self.prompt_template = file.read()

        placeholders = detect_placeholders(self.prompt_template)

        # Clear existing input fields
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        self.placeholder_vars = {}
        for placeholder in placeholders:
            tk.Label(self.scrollable_frame, text=f"{placeholder.title()}:", font=("Arial", 10)).pack(anchor="w")
            var = tk.StringVar()
            entry = tk.Entry(self.scrollable_frame, textvariable=var, width=40)
            entry.pack(pady=2)
            self.placeholder_vars[placeholder] = var

    def generate_form(self):
        if not hasattr(self, "prompt_template"):
            messagebox.showerror("Error", "Please select a form first!")
            return

        user_data = {key: var.get() for key, var in self.placeholder_vars.items()}

        if any(not value for value in user_data.values()):
            messagebox.showerror("Error", "Please fill in all the fields!")
            return

        try:
            prompt = self.prompt_template.format(**user_data)
        except KeyError as e:
            messagebox.showerror("Error", f"Missing value for {e}.")
            return

        generated_content = generate_text_with_transformers(prompt)

        output_pdf_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save As"
        )
        if output_pdf_path:
            save_to_pdf(generated_content, output_pdf_path)
            messagebox.showinfo("Success", f"Form saved as {output_pdf_path}")

# Main Application
def main():
    root = tk.Tk()
    app = FormApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
