import random
import string
import PyQt6.QtWidgets as qtw
import PyQt6.QtGui as qtg
import PyQt6.QtCore as qtc

class MainWindow(qtw.QWidget):
    def __init__(self):
        super().__init__()
        # set title
        self.setWindowTitle("PASSWORD MANAGER")
        
        # set fixed size
        self.setFixedSize(400, 625)
    
        # set vertical layout
        self.setLayout(qtw.QVBoxLayout())

        # create a tab widget
        self.tab_widget = qtw.QTabWidget()
        self.layout().addWidget(self.tab_widget)

        # create tabs
        self.accounts_tab = qtw.QWidget()
        self.generator_tab = qtw.QWidget()
        self.settings_tab = qtw.QWidget()

        # add tabs to tab widget
        self.tab_widget.addTab(self.accounts_tab, "Accounts")
        self.tab_widget.addTab(self.generator_tab, "Generator")
        self.tab_widget.addTab(self.settings_tab, "Settings")

        # set layouts for tabs
        self.accounts_tab.setLayout(qtw.QVBoxLayout())
        self.generator_tab.setLayout(qtw.QVBoxLayout())
        self.settings_tab.setLayout(qtw.QVBoxLayout())

        # add generator functionality to generator tab
        self.setup_generator_tab()

        # add accounts functionality to accounts tab
        self.setup_accounts_tab()

        # add settings functionality to settings tab
        self.setup_settings_tab()

        # show the app
        self.show()

    def setup_generator_tab(self):
        # create a slider
        self.my_slider = qtw.QSlider(qtc.Qt.Orientation.Horizontal)
        self.my_slider.setMinimum(8)
        self.my_slider.setMaximum(100)
        self.my_slider.setValue(12)
        self.my_slider.setTickInterval(10)
        self.my_slider.setTickPosition(qtw.QSlider.TickPosition.NoTicks)
        self.my_slider.valueChanged.connect(self.update_slider_label)

        # put slider on screen
        self.generator_tab.layout().addWidget(self.my_slider)

        # create a horizontal layout for the label and input field
        label_input_layout = qtw.QHBoxLayout()

        # create a label
        my_label = qtw.QLabel("Number of Characters:")
        my_label.setFont(qtg.QFont('Helvetica', 13))
        label_input_layout.addWidget(my_label)

        # create an input text field for the slider value
        self.slider_input = qtw.QLineEdit("12")
        self.slider_input.setValidator(qtg.QIntValidator(8, 100))
        self.slider_input.setFixedWidth(50)  # set the fixed width for the input field
        self.slider_input.setFont(qtg.QFont('Helvetica', 18))
        self.slider_input.textChanged.connect(self.update_slider_from_input)
        label_input_layout.addWidget(self.slider_input)

        # add the horizontal layout to the main layout
        self.generator_tab.layout().addLayout(label_input_layout)

        # create checkboxes
        self.include_numbers = qtw.QCheckBox("Include Numbers")
        self.include_numbers.setChecked(True)
        self.generator_tab.layout().addWidget(self.include_numbers)

        self.include_special_chars = qtw.QCheckBox("Include Special Characters")
        self.include_special_chars.setChecked(True)
        self.generator_tab.layout().addWidget(self.include_special_chars)

        # create a button
        my_button = qtw.QPushButton("Generate", clicked=self.press_it)
        self.generator_tab.layout().addWidget(my_button)

        # create a QTextEdit to display the generated password
        self.password_display = qtw.QTextEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setFont(qtg.QFont('Helvetica', 20))
        self.password_display.setFixedSize(380, 100)  # set the size restrictions
        self.generator_tab.layout().addWidget(self.password_display)

        # create a clipboard icon button
        clipboard_icon = qtg.QIcon.fromTheme("edit-copy")
        self.clipboard_button = qtw.QPushButton("Copy To Clipboard")
        self.clipboard_button.clicked.connect(self.copy_to_clipboard)
        self.generator_tab.layout().addWidget(self.clipboard_button)

    def setup_accounts_tab(self):
        # create a form layout for the username and password inputs
        form_layout = qtw.QFormLayout()

        # create a line edit for the username
        self.username_input = qtw.QLineEdit()
        form_layout.addRow("Username:", self.username_input)

        # create a line edit for the password
        self.password_input = qtw.QLineEdit()
        self.password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        form_layout.addRow("Password:", self.password_input)

        # create a button to add the account
        add_account_button = qtw.QPushButton("Add Account", clicked=self.add_account)
        form_layout.addRow(add_account_button)

        # add the form layout to the accounts tab
        self.accounts_tab.layout().addLayout(form_layout)

        # create a list widget to display the saved accounts
        self.accounts_list = qtw.QListWidget()
        self.accounts_tab.layout().addWidget(self.accounts_list)

    def setup_settings_tab(self):
        # create a dropdown for safe timeout
        self.safe_timeout_label = qtw.QLabel("Safe Timeout:")
        self.safe_timeout_dropdown = qtw.QComboBox()
        self.safe_timeout_dropdown.addItems(["5 minutes", "10 minutes", "15 minutes", "Never"])

        # add dropdown to the settings tab
        self.settings_tab.layout().addWidget(self.safe_timeout_label)
        self.settings_tab.layout().addWidget(self.safe_timeout_dropdown)

    def add_account(self):
        # get the username and password from the inputs
        username = self.username_input.text()
        password = self.password_input.text()

        # add the username and password to the accounts list
        if username and password:
            self.accounts_list.addItem(f"Username: {username}, Password: {password}")
            self.username_input.clear()
            self.password_input.clear()

    def generate_password(self, length, include_special_chars, include_numbers):
        if length < 4:
            raise ValueError("Password length should be at least 4 characters.")

        # Define character sets for password generation
        lowercase_letters = string.ascii_lowercase
        uppercase_letters = string.ascii_uppercase
        digits = string.digits if include_numbers else ''
        symbols = string.punctuation if include_special_chars else ''
        
        # Ensure at least one character set is selected
        if not (lowercase_letters or uppercase_letters or digits or symbols):
            raise ValueError("At least one character set must be enabled.")
        
        # Combine selected character sets
        all_characters = lowercase_letters + uppercase_letters + digits + symbols
        
        # Ensure the password includes at least one character from each enabled set
        password = ''
        if lowercase_letters:
            password += random.choice(lowercase_letters)
        if uppercase_letters:
            password += random.choice(uppercase_letters)
        if digits:
            password += random.choice(digits)
        if symbols:
            password += random.choice(symbols)
        
        # Fill the rest of the password with random characters from all_characters
        password += ''.join(random.choice(all_characters) for _ in range(length - len(password)))
        
        # Shuffle the password to make it more random
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)
        
        return password

    def press_it(self):
        length = self.my_slider.value()
        include_special_chars = self.include_special_chars.isChecked()
        include_numbers = self.include_numbers.isChecked()
        password = self.generate_password(length, include_special_chars, include_numbers)
        self.password_display.setText(password)

    def update_slider_label(self):
        value = self.my_slider.value()
        self.slider_input.setText(str(value))

    def update_slider_from_input(self):
        value = self.slider_input.text()
        if value.isdigit():
            self.my_slider.setValue(int(value))

    def copy_to_clipboard(self):
        clipboard = qtw.QApplication.clipboard()
        clipboard.setText(self.password_display.toPlainText())

app = qtw.QApplication([])
mw = MainWindow()
app.exec()
