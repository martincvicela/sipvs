import java.awt.Desktop;
import java.awt.EventQueue;
import java.awt.Font;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.JButton;

import org.jdatepicker.impl.JDatePanelImpl;
import org.jdatepicker.impl.JDatePickerImpl;
import org.jdatepicker.impl.UtilDateModel;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.awt.event.ActionEvent;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JTextPane;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;

class DateLabelFormatter extends AbstractFormatter {

	private static final long serialVersionUID = 1L;
	private String datePattern = "yyyy-MM-dd";
	private SimpleDateFormat dateFormatter = new SimpleDateFormat(datePattern);

	@Override
	public Object stringToValue(String text) throws ParseException {
		return dateFormatter.parseObject(text);
	}

	@Override
	public String valueToString(Object value) throws ParseException {
		if (value != null) {
			Calendar cal = (Calendar) value;
			return dateFormatter.format(cal.getTime());
		}

		return "";
	}
}

public class MainGUI {

	private JFrame frame;
	private JTable table;
	private JTextField txtName;
	private JTextField txtEmail;
	private JTextField textField_telephone;
	private JTextField txtCity;
	private DogModel modeldog = new DogModel();
	JDatePanelImpl datePanel;
	JDatePickerImpl datePicker;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainGUI window = new MainGUI();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public MainGUI() {
		initialize();
	}

	/**
	 * Creates DogEvidenceRecordfrom GUI
	 */
	public DogEvidenceRecord getDogEvidenceRecordFromGUI() {
		DogEvidenceRecord record = new DogEvidenceRecord();
		record.dogs = modeldog.getDogs();
		record.requestDateAll = (Date) datePicker.getModel().getValue();
		record.name = txtName.getText();
		record.contact = new Contact(textField_telephone.getText(), txtEmail.getText());
		record.city = txtCity.getText();
		return record;
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.getContentPane().setEnabled(false);
		frame.setBounds(100, 100, 715, 547);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		UtilDateModel model = new UtilDateModel();
		model.setDate(2017, 9, 3);
		model.setSelected(true);

		Properties p = new Properties();
		p.put("text.today", "Today");
		p.put("text.month", "Month");
		p.put("text.year", "Year");
		datePanel = new JDatePanelImpl(model, p);
		datePicker = new JDatePickerImpl(datePanel, new DateLabelFormatter());
		datePicker.setBounds(155, 325, 260, 87);

		frame.getContentPane().add(datePicker);

		JLabel lbl_NameAndSurname = new JLabel(
				"Obchodn\u00E9 meno / meno a priezvisko vlastn\u00EDka (dr\u017Eite\u013Ea) psa:");
		Font f = lbl_NameAndSurname.getFont();
		lbl_NameAndSurname.setBounds(10, 47, 360, 14);
		lbl_NameAndSurname.setFont(f.deriveFont(f.getStyle() ^ Font.BOLD));
		frame.getContentPane().add(lbl_NameAndSurname);

		table = new JTable();
		modeldog.fireTableDataChanged();
		table.setModel(modeldog);
		JTableHeader header = table.getTableHeader();
		header.setFont(f.deriveFont(Font.BOLD));

		JScrollPane scroll = new JScrollPane(table);
		scroll.setBounds(7, 185, 666, 102);
		frame.getContentPane().add(scroll);

		JButton btnAddDog = new JButton("+");
		btnAddDog.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Date selectedDate = (Date) datePicker.getModel().getValue();
				DateFormat df = new SimpleDateFormat("yyyy-MM-dd"); // e.g.
																	// MM/dd/yyyy
																	// HH:mm:ss
				String reportDate = df.format(selectedDate);
				JOptionPane.showMessageDialog(null, "My Goodness, this is so beautiful" + reportDate);
				modeldog.addRow(new Dog("black", "Rex", "German Shepherd", 9875));
				modeldog.fireTableDataChanged();
			}
		});
		btnAddDog.setBounds(584, 291, 89, 23);
		frame.getContentPane().add(btnAddDog);

		JButton btn_SaveXml = new JButton("Ulo\u017E XML");
		btn_SaveXml.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				DogEvidenceRecord record = getDogEvidenceRecordFromGUI();
				ConvertDogRecordToXml convert = new ConvertDogRecordToXml(record);
			}
		});
		btn_SaveXml.setBounds(573, 473, 103, 23);
		frame.getContentPane().add(btn_SaveXml);

		txtName = new JTextField();
		txtName.setText("Chuck Norris");
		txtName.setBounds(380, 44, 296, 20);
		frame.getContentPane().add(txtName);
		txtName.setColumns(10);

		txtEmail = new JTextField();
		txtEmail.setText("chuck.norris@gmail.com");
		txtEmail.setBounds(216, 133, 198, 20);
		frame.getContentPane().add(txtEmail);
		txtEmail.setColumns(10);

		JLabel lbl_Email = new JLabel("e-mail");
		lbl_Email.setBounds(129, 136, 77, 14);
		lbl_Email.setFont(f.deriveFont(f.getStyle() ^ Font.BOLD));
		frame.getContentPane().add(lbl_Email);

		JLabel lbl_telephoneNo = new JLabel("telef\u00F3n");
		lbl_telephoneNo.setBounds(129, 94, 77, 14);
		lbl_telephoneNo.setFont(f.deriveFont(f.getStyle() ^ Font.BOLD));
		frame.getContentPane().add(lbl_telephoneNo);

		textField_telephone = new JTextField();
		textField_telephone.setText("0901 123 456");
		textField_telephone.setBounds(216, 91, 198, 20);
		frame.getContentPane().add(textField_telephone);
		textField_telephone.setColumns(10);

		JButton btn_ValidateXml = new JButton("Validuj Xml");
		btn_ValidateXml.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Validate XMLValidator = new Validate();
				File xml = new File("file.xml");
				File xsd = new File("file.xsd");
				System.out.println(XMLValidator.validateXML(xml, xsd));
			}
		});
		btn_ValidateXml.setBounds(10, 473, 108, 23);
		frame.getContentPane().add(btn_ValidateXml);

		JButton btn_TransformToHtml = new JButton("Zobraz formulár");
		btn_TransformToHtml.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (!Desktop.isDesktopSupported()) {
					System.err.println("Desktop not supported!");
					System.exit(-1);
				}

				Desktop desktop = Desktop.getDesktop();
				File file = new File("file.xml");

				if (desktop.isSupported(Desktop.Action.OPEN)) {
					try {
						desktop.open(file);
					} catch (IOException ioe) {
						System.err.println("Unable to open: " + file.getName());
					}
				}
			}
		});
		btn_TransformToHtml.setBounds(128, 473, 136, 23);
		frame.getContentPane().add(btn_TransformToHtml);

		txtCity = new JTextField();
		txtCity.setText("Bratislava");
		txtCity.setBounds(7, 327, 103, 20);
		frame.getContentPane().add(txtCity);
		txtCity.setColumns(10);

		JLabel lblPrihlseniePsaDo = new JLabel("Prihl\u00E1senie psov do evidencie");
		lblPrihlseniePsaDo.setBounds(282, 11, 171, 14);
		frame.getContentPane().add(lblPrihlseniePsaDo);

		JLabel lblKontakt = new JLabel("Kontakt: ");
		lblKontakt.setBounds(10, 94, 71, 14);
		lblKontakt.setFont(f.deriveFont(f.getStyle() ^ Font.BOLD));
		frame.getContentPane().add(lblKontakt);

		JLabel lblNewLabel = new JLabel("d\u0148a");
		lblNewLabel.setBounds(120, 330, 46, 14);
		lblNewLabel.setFont(f.deriveFont(f.getStyle() ^ Font.BOLD));
		frame.getContentPane().add(lblNewLabel);

		JLabel lblNewLabel_1 = new JLabel("Zoznam psov:");
		lblNewLabel_1.setBounds(7, 160, 111, 14);
		lblNewLabel_1.setFont(f.deriveFont(f.getStyle() ^ Font.BOLD));
		frame.getContentPane().add(lblNewLabel_1);

		JButton buttonRemoveSelectedDog = new JButton("-");
		buttonRemoveSelectedDog.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				try {
					int dialogResult = JOptionPane.showConfirmDialog(null,
							"Prajete si odobrat psa s evidenèným èíslom: "
									+ modeldog.getDogAtIndex(table.getSelectedRow()).eNumber,
							null, JOptionPane.YES_NO_OPTION);
					if (dialogResult == JOptionPane.YES_OPTION) {
						modeldog.removeRowAtIndex(table.getSelectedRow());
						modeldog.fireTableDataChanged();
					}
				} catch (Exception e) {
					JOptionPane.showMessageDialog(null, "Zrejme ste nevybrali z ponuky psov.",
							"Zrejme ste nevybrali z ponuky", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		buttonRemoveSelectedDog.setBounds(481, 291, 89, 23);
		frame.getContentPane().add(buttonRemoveSelectedDog);
	}
}
