package mflix.api.daos;

import com.mongodb.MongoClientSettings;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Filters;
import mflix.api.models.BookingDTO;
import mflix.api.models.FilmSchedule;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import static com.mongodb.client.model.Updates.set;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.bson.codecs.configuration.CodecRegistries.fromProviders;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

@Configuration
public class ScheduleDao extends AbstractMFlixDao {
  private final MongoCollection<FilmSchedule> scheduleCollection;

  private final Logger log;

  @Autowired
  public ScheduleDao(
      MongoClient mongoClient, @Value("${spring.mongodb.database}") String databaseName) {
    super(mongoClient, databaseName);
    CodecRegistry pojoCodecRegistry =
        fromRegistries(
            MongoClientSettings.getDefaultCodecRegistry(),
            fromProviders(PojoCodecProvider.builder().automatic(true).build()));

    scheduleCollection =
        db.getCollection("schedules", FilmSchedule.class).withCodecRegistry(pojoCodecRegistry);
    log = LoggerFactory.getLogger(this.getClass());
  }

  public FilmSchedule addSchedule(FilmSchedule filmSchedule) {

    scheduleCollection.insertOne(filmSchedule);
    return filmSchedule;
  }

  public List<BookingDTO> getBooking(String movieId, Date showing) {

    return null;
  }

  public FilmSchedule getScheduleByMovieIdAndDate(String movieId, Date date) {
    Bson movieFilter = Aggregates.match(Filters.eq("movie_id", new ObjectId(movieId)));
    Bson dateFilter = Aggregates.match(Filters.eq("date", date));
    List<Bson> pipeline = new ArrayList<>();
    pipeline.add(movieFilter);
   pipeline.add(dateFilter);
    AggregateIterable<FilmSchedule> iterable = scheduleCollection.aggregate(pipeline);
//    AggregateIterable<Document> iterable = bookingCollection2.aggregate(pipeline);
//    List<Document> documents = new ArrayList<>();
    FilmSchedule filmSchedule = iterable.first();

    //    Bson
    return filmSchedule;
  }

  public boolean updateSchedule(FilmSchedule filmSchedule) {
    Bson queryFilter =
        Filters.and(
            Filters.eq("movie_id", filmSchedule.getMovieObjectId()),
            Filters.eq("date", filmSchedule.getDate()));

    scheduleCollection.updateOne(queryFilter, set("time", filmSchedule.getTime()));

    return true;
  }
}
