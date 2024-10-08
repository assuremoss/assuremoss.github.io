package org.sasanlabs.service.car;

/** @author preetkaran20@gmail.com KSASAN */
public class CarInformation {
    private int id;
    private String name;
    private String imagePath;

    public CarInformation() {}

    public CarInformation(int id, String carName, String imagePath) {
        super();
        this.id = id;
        this.name = carName;
        this.imagePath = imagePath;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImagePath() {
        return imagePath;
    }

    public void setImagePath(String imagePath) {
        this.imagePath = imagePath;
    }
}
