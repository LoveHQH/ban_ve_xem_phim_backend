package mflix.api.models;

public class Region {
    private String region;
    private String lang;

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    @Override
    public String toString() {
        return "Region{" + "region='" + region + '\'' + ", lang='" + lang + '\'' + '}';
    }
}
