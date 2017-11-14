import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import javax.swing.JTextArea;
import javax.swing.JLabel;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.awt.event.ActionEvent;
import javax.swing.JTextPane;

public class VerifierGUI extends JDialog {

	private final JPanel contentPanel = new JPanel();

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			VerifierGUI dialog = new VerifierGUI();
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Create the dialog.
	 */
	public VerifierGUI() {
		setTitle("OverovaË");
		setBounds(100, 100, 450, 300);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		JTextArea verifier_textArea = new JTextArea();
		verifier_textArea.setBounds(10, 84, 414, 144);
		contentPanel.add(verifier_textArea);
		
		JLabel lblNewLabel = new JLabel("V˝sledok overenia");
		lblNewLabel.setBounds(10, 59, 112, 14);
		contentPanel.add(lblNewLabel);
		
		JTextPane pathTextPane = new JTextPane();
		pathTextPane.setText("ProsÌm, pouûi tlaËidlo \"Otvor s˙bor\" a vyber s˙bor");
		pathTextPane.setEditable(false);
		pathTextPane.setBounds(10, 31, 414, 20);
		contentPanel.add(pathTextPane);
		
		JLabel pathLabel_1 = new JLabel("Vybrat· cesta:");
		pathLabel_1.setBounds(10, 6, 77, 14);
		contentPanel.add(pathLabel_1);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("Otvor s˙bor");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent arg0) {
						
						JFileChooser fileChooser = new JFileChooser();
						fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
						int result = fileChooser.showOpenDialog(null);
						if (result == JFileChooser.APPROVE_OPTION) {
						    File selectedFile = fileChooser.getSelectedFile();
						    pathTextPane.setText(selectedFile.getAbsolutePath());
						    
						    //todo fix this
						    try {
								Validator validator = new Validator(fileChooser.getSelectedFile());
								int validatorResult = validator.validate();
								if(validatorResult == 0)
									verifier_textArea.setText("Vöetko vyzer· OK");
								else
									verifier_textArea.setText("Pravidlo " + validatorResult + " poruöenÈ");
									
							} catch (ParserConfigurationException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (SAXException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						    
						}
						
					}
				});
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
			{
				JButton cancelButton = new JButton("Zruöiù");
				cancelButton.setActionCommand("Zruöiù");
				buttonPane.add(cancelButton);
			}
		}
	}
}
