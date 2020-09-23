package mflix.api.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import net.bytebuddy.agent.builder.AgentBuilder;
import org.bson.codecs.pojo.annotations.BsonId;
import org.bson.codecs.pojo.annotations.BsonIgnore;
import org.bson.codecs.pojo.annotations.BsonProperty;
import org.bson.types.ObjectId;

import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;

public class FilmSchedule {
  @JsonProperty("_id")
  @BsonIgnore
  private String id;

  @BsonId @JsonIgnore private ObjectId oid;

  @JsonProperty("movie_id")
  @BsonIgnore
  private String movieId;

  @BsonProperty("movie_id")
  @JsonIgnore
  private ObjectId movieObjectId;

  private LinkedHashSet<String> time;


  private Date date;

  public Date getDate() {
    return date;
  }

  public void setDate(Date date) {
    this.date = date;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
    this.oid = new ObjectId(id);
  }

  public String getMovieId() {
    return movieId;
  }

  public void setMovieId(String movieId) {
    this.movieId = movieId;
    this.movieObjectId = new ObjectId(movieId);
  }

  public void setOid(ObjectId oid) {
    this.oid = oid;
    this.id = oid.toHexString();
  }

  public ObjectId getOid() {
    return oid;
  }

  public ObjectId getMovieObjectId() {
    return movieObjectId;
  }

  public void setMovieObjectId(ObjectId movieObjectId) {
    this.movieObjectId = movieObjectId;
    this.movieId = movieObjectId.toHexString();
  }

  public LinkedHashSet<String> getTime() {
    return time;
  }

  public void setTime(LinkedHashSet<String> time) {
    this.time = time;
  }
}
