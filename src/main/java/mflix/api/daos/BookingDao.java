package mflix.api.daos;

import com.mongodb.MongoClientSettings;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Sorts;
import mflix.api.models.BookingDTO;
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

import javax.print.Doc;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.bson.codecs.configuration.CodecRegistries.fromProviders;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

@Configuration
public class BookingDao extends AbstractMFlixDao {
    private final MongoCollection<BookingDTO> bookingCollection;
    private final MongoCollection<Document> bookingCollection2;

    private final Logger log;

    @Autowired
    public BookingDao(
            MongoClient mongoClient, @Value("${spring.mongodb.database}") String databaseName) {
        super(mongoClient, databaseName);
        CodecRegistry pojoCodecRegistry =
                fromRegistries(
                        MongoClientSettings.getDefaultCodecRegistry(),
                        fromProviders(PojoCodecProvider.builder().automatic(true).build()));

        bookingCollection =
                db.getCollection("bookings", BookingDTO.class).withCodecRegistry(pojoCodecRegistry);
        bookingCollection2 = db.getCollection("bookings");
        log = LoggerFactory.getLogger(this.getClass());
    }

    public boolean addBooking(BookingDTO bookingDTO) {
        bookingCollection.insertOne(bookingDTO);
        System.out.println("adding booking");
        return true;
    }

    public List<BookingDTO> getBooking(String movieId, Date showing) {
        // DONE> Ticket: Subfield Text Search - implement the expected cast
        // filter and sort
        List<BookingDTO> bookings = new ArrayList<>();
        List<Bson> pipeline = new ArrayList<>();
        // match stage to find movie
        Bson matchId = Aggregates.match(Filters.eq("movie._id", movieId));
        System.out.println("get booking dao");
        System.out.println(showing);
        Bson matchShowing = Aggregates.match(Filters.eq("showing", showing));
        pipeline.add(matchId);
        pipeline.add(matchShowing);
        AggregateIterable<BookingDTO> iterable = bookingCollection.aggregate(pipeline);
//    AggregateIterable<Document> iterable = bookingCollection2.aggregate(pipeline);
//    List<Document> documents = new ArrayList<>();
        iterable.into(bookings);
//    iterable.into(documents);

        return bookings;
    }


    public List<BookingDTO> getall() {
        // DONE> Ticket: Subfield Text Search - implement the expected cast
        // filter and sort
        List<BookingDTO> bookings = new ArrayList<>();
        List<Bson> pipeline = new ArrayList<>();
        // match stage to find movie
        System.out.println("get booking dao");
//    System.out.println(showing);
        SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm");
        try {
            Date showing = sf.parse(sf.format(new Date()));
//            Date showing = new Date();
            Bson matchShowing = Aggregates.match(Filters.gte("showing", showing));
            System.out.println(showing);
            pipeline.add(matchShowing);
            AggregateIterable<BookingDTO> iterable = bookingCollection.aggregate(pipeline);

            iterable.into(bookings);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return bookings;
    }
}
