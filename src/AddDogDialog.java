import java.util.Date;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFormattedTextField;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.text.NumberFormatter;

import org.jdatepicker.impl.JDatePanelImpl;
import org.jdatepicker.impl.JDatePickerImpl;
import org.jdatepicker.impl.UtilDateModel;

import java.awt.event.ActionListener;
import java.text.NumberFormat;
import java.util.Properties;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.SpringLayout;

public class AddDogDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	public Dog dog = new Dog();
	public boolean add = false;
	JDatePanelImpl datePanel;
	JDatePickerImpl datePicker;
	private JTextField textField_Name;
	private JTextField textField_Breed;
	private JTextField textField_Gender;
	private JTextField textField_Colour;
	private JFormattedTextField textField_EvidenceNo;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			AddDogDialog dialog = new AddDogDialog();
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Create the dialog.
	 */
	public AddDogDialog() {
		JPanel pan=new JPanel();
		pan.setLayout(new FlowLayout());
		getContentPane().add(pan);
		setBounds(100, 100, 450, 335);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						dog.name = textField_Name.getText();
						dog.birthDateWithTime = (Date) datePicker.getModel().getValue();
						dog.breed = textField_Breed.getText();
						dog.eNumber =  Integer.parseInt(textField_EvidenceNo.getText().replaceAll(",", ""));
						dog.colour = textField_Colour.getText();
						dog.gender = textField_Gender.getText();
						add = true;
						dispose();
					}
				});
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
			{
				JButton cancelButton = new JButton("Cancel");
				cancelButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						add = false;
						dispose();
					}
				});
				cancelButton.setActionCommand("Cancel");
				buttonPane.add(cancelButton);
			}
		}
		
		UtilDateModel model = new UtilDateModel();
		model.setDate(2017, 9, 3);
		model.setSelected(true);

		Properties p = new Properties();
		p.put("text.today", "Today");
		p.put("text.month", "Month");
		p.put("text.year", "Year");
		datePanel = new JDatePanelImpl(model, p);
		contentPanel.setLayout(null);
		datePicker = new JDatePickerImpl(datePanel, new DateLabelFormatter());
		SpringLayout springLayout = (SpringLayout) datePicker.getLayout();
		datePicker.setBounds(155, 20, 190, 20);
		contentPanel.add(datePicker);
		
		JLabel lblNewLabel = new JLabel("Pohlavie psa");
		lblNewLabel.setBounds(17, 146, 130, 14);
		contentPanel.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel("Meno psa");
		lblNewLabel_1.setBounds(17, 64, 130, 14);
		contentPanel.add(lblNewLabel_1);
		
		JLabel lblNewLabel_2 = new JLabel("Pemeno psa");
		lblNewLabel_2.setBounds(17, 107, 130, 14);
		contentPanel.add(lblNewLabel_2);
		
		textField_Name = new JTextField();
		textField_Name.setBounds(157, 61, 171, 20);
		contentPanel.add(textField_Name);
		textField_Name.setColumns(10);
		
		textField_Breed = new JTextField();
		textField_Breed.setBounds(157, 104, 171, 20);
		contentPanel.add(textField_Breed);
		textField_Breed.setColumns(10);
		
		textField_Gender = new JTextField();
		textField_Gender.setBounds(157, 143, 171, 20);
		contentPanel.add(textField_Gender);
		textField_Gender.setColumns(10);
		
		textField_Colour = new JTextField();
		textField_Colour.setBounds(157, 186, 171, 20);
		contentPanel.add(textField_Colour);
		textField_Colour.setColumns(10);
		
		JLabel lblNewLabel_3 = new JLabel("Farba psa");
		lblNewLabel_3.setBounds(17, 189, 130, 14);
		contentPanel.add(lblNewLabel_3);
		
		NumberFormat integerFormat = NumberFormat.getIntegerInstance();
		NumberFormatter numberFormatter = new NumberFormatter(integerFormat);
		numberFormatter.setValueClass(Integer.class); //optional, ensures you will always get a long value
		numberFormatter.setAllowsInvalid(false); //this is the key!!
		numberFormatter.setMinimum(0); //Optional
		textField_EvidenceNo = new JFormattedTextField (numberFormatter);
		textField_EvidenceNo.setBounds(157, 229, 171, 20);
		contentPanel.add(textField_EvidenceNo);
		textField_EvidenceNo.setColumns(10);
		
		JLabel lblNewLabel_4 = new JLabel("Evidence cislo psa");
		lblNewLabel_4.setBounds(17, 232, 130, 14);
		contentPanel.add(lblNewLabel_4);
		
		JLabel lblNewLabel_5 = new JLabel("Datum narodenia psa");
		lblNewLabel_5.setBounds(17, 20, 130, 14);
		contentPanel.add(lblNewLabel_5);
	}
}
