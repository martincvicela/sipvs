import java.util.ArrayList;


import javax.swing.table.AbstractTableModel;

public class DogModel extends AbstractTableModel {

private static final long serialVersionUID = 1L;
private static final String[] columnNames = { "Datum narodenia", "Meno", "Plemeno", "Pohlavie", "Farba", "Evidenèné èíslo"};
private ArrayList<Dog> dogs;

public ArrayList<Dog> getDogs() {
	return dogs;
}

public void setDogs(ArrayList<Dog> dogs) {
	this.dogs = dogs;
}

public DogModel(){
    dogs =  new ArrayList<Dog>();
    dogs.add(new Dog("primalex", "Jawa", "Labrador Retriever", 14789));
    dogs.add(new Dog());
    dogs.add(new Dog("Belinka", "Trabant", "exception throw", 654));
}

public void addRow(Dog rowData)
{
	dogs.add(rowData);
}

public Dog getDogAtIndex(int index)
{
	return dogs.get(index);
}

public void removeRowAtIndex(int index)
{
	dogs.remove(index);
}


@Override
public int getColumnCount() {
    // TODO Auto-generated method stub
    return columnNames.length;
}

@Override
public int getRowCount() {
    return dogs.size();
}

@Override
public String getColumnName(int column) {
    return columnNames[column];
}

@Override
public Object getValueAt(int rowIndex, int columnIndex) {
    switch (columnIndex) {
    case 0:
    	return dogs.get(rowIndex).birthDate;
    case 1:
    	return dogs.get(rowIndex).name;
    case 2:
    	return dogs.get(rowIndex).breed;
    case 3:
    	return dogs.get(rowIndex).gender;
    case 4:
    	return dogs.get(rowIndex).colour;  
    case 5:
    	return dogs.get(rowIndex).eNumber;	
    }
    return null;
}
}