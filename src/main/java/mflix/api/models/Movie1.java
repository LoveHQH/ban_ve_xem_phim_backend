package mflix.api.models;

public class Movie1 {

  private String id;
  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  //    private String title;
  //    private String poster;
  //    private List<Integer> genres = null;
  //    private String release_date;
  //    private Double average_score;
  //    private String overview;

  //    public String getTitle() {
  //        return title;
  //    }
  //
  //    public void setTitle(String title) {
  //        this.title = title;
  //    }


  //    public String getPoster() {
  //        return poster;
  //    }
  //
  //    public void setPoster(String poster) {
  //        this.poster = poster;
  //    }
  //
  //    public List<Integer> getGenres() {
  //        return genres;
  //    }
  //
  //    public void setGenres(List<Integer> genres) {
  //        this.genres = genres;
  //    }
  //
  //    public String getRelease_date() {
  //        return release_date;
  //    }
  //
  //    public void setRelease_date(String release_date) {
  //        this.release_date = release_date;
  //    }
  //
  //    public Double getAverage_score() {
  //        return average_score;
  //    }
  //
  //    public void setAverage_score(Double average_score) {
  //        this.average_score = average_score;
  //    }
  //
  //    public String getOverview() {
  //        return overview;
  //    }
  //
  //    public void setOverview(String overview) {
  //        this.overview = overview;
  //    }
  //
  //    @Override
  //    public String toString() {
  //        return "Movie1{"
  //                + "title='"
  //                + title
  //                + '\''
  //                + ", id="
  //                + _id
  //                + ", poster='"
  //                + poster
  //                + '\''
  //                + ", genres="
  //                + genres
  //                + ", releaseDate='"
  //                + release_date
  //                + '\''
  //                + ", averageScore="
  //                + average_score
  //                + ", overview='"
  //                + overview
  //                + '\''
  //                + '}';
  //    }
  @Override
  public String toString() {
    return "Movie1{" + "_id=" + id + '}';
  }
}
