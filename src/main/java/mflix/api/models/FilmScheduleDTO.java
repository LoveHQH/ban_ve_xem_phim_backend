package mflix.api.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.bson.codecs.pojo.annotations.BsonProperty;
import org.bson.types.ObjectId;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;

public class FilmScheduleDTO {

  private String movieId;

  private LinkedHashSet<String> time;

  @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
  private Date date;

  public String getMovieId() {
    return movieId;
  }

  public void setMovieId(String movieId) {
    this.movieId = movieId;
  }

  public LinkedHashSet<String> getTime() {
    return time;
  }

  public void setTime(LinkedHashSet<String> time) {
    this.time = time;
  }

  public Date getDate() {
    return date;
  }

  public void setDate(Date date) {
    this.date = date;
  }

  @Override
  public String toString() {
    return "FilmScheduleDTO{"
        + "movieId='"
        + movieId
        + '\''
        + ", time="
        + time
        + ", date="
        + date
        + '}';
  }
}
