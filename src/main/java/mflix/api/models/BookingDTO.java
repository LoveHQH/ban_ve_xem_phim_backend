package mflix.api.models;

import java.util.Date;
import java.util.List;

public class BookingDTO {

  private Movie1 movie;
  private Date showing;

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  private String username ;

  @Override
  public String toString() {
    return "BookingDTO{" +
            "movie=" + movie +
            ", showing=" + showing +
            ", seats=" + seats +
            ", username " + username +
            '}';
  }

  private List<String> seats;

  public Movie1 getMovie() {
    return movie;
  }

  public void setMovie(Movie1 movie) {
    this.movie = movie;
  }

  public Date getShowing() {
    return showing;
  }

  public void setShowing(Date showing) {
    this.showing = showing;
  }

  public List<String> getSeats() {
    return seats;
  }

  public void setSeats(List<String> seats) {
    this.seats = seats;
  }

}
