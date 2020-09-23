package mflix.api.daos;

import mflix.api.models.*;
import org.bson.Document;

import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;

import org.bson.conversions.Bson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@SuppressWarnings("unchecked")
public class MovieDocumentMapper {

    private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static Logger log = LoggerFactory.getLogger(MovieDocumentMapper.class.getName());

    public static MovieTitle mapToMovieTitle(Document document) {
        MovieTitle movie = new MovieTitle();
        movie.setId(document.getObjectId("_id").toHexString());
        movie.setTitle(MessageFormat.format("{0}", document.get("title")));
        return movie;
    }

    public static Movie mapToMovie(Bson bson) {

        Movie movie = new Movie();
        Document document = (Document) bson;
        try {
            movie.setId(document.getObjectId("_id").toHexString());
            movie.setTitle(MessageFormat.format("{0}", document.get("title")));
            movie.setCast((List<String>) document.get("cast"));
            movie.setPlog(document.getString("plot"));
            movie.setFullPlot(document.getString("fullplot"));

            movie.setLastUpdated(parseDate(document.get("lastupdated")));

            movie.setType(document.getString("type"));
            movie.setDirectors((List<String>) document.get("directors"));
            movie.setWriters((List<String>) document.get("writers"));

            if (document.containsKey("imdb")) {
                movie.setImdb(mapToIMDB((Document) document.get("imdb")));
            }

            movie.setCountries((List<String>) document.get("countries"));
            movie.setGenres((List<String>) document.get("genres"));

            if (document.containsKey("tomatoes")) {
                movie.setTomatoes(mapToRottenTomatoes((Document) document.get("tomatoes")));
            }

            movie.setPoster(document.getString("poster"));

            if (document.containsKey("comments")) {
                List<Comment> comments = new ArrayList<>();
                for (Document commentDoc : (List<Document>) document.get("comments")) {
                    comments.add(parseComment(commentDoc));
                }
                movie.setComments(comments);
            }

        } catch (Exception e) {
            log.warn("Unable to map document `{}` to `Movie` object: {} ", document, e.getMessage());
            log.warn("Skipping document");
        }
        return movie;
    }

    public static MovieSchedule mapToMovieSchedule(Bson bson) {

        MovieSchedule movie = new MovieSchedule();
        Document document = (Document) bson;
        try {
            movie.setId(document.getObjectId("_id").toHexString());
            movie.setTitle(MessageFormat.format("{0}", document.get("title")));
            movie.setCast((List<String>) document.get("cast"));
            movie.setPlog(document.getString("plot"));
            movie.setFullPlot(document.getString("fullplot"));

            movie.setLastUpdated(parseDate(document.get("lastupdated")));

            movie.setType(document.getString("type"));
            movie.setDirectors((List<String>) document.get("directors"));
            movie.setWriters((List<String>) document.get("writers"));

            if (document.containsKey("imdb")) {
                movie.setImdb(mapToIMDB((Document) document.get("imdb")));
            }

            movie.setCountries((List<String>) document.get("countries"));
            movie.setGenres((List<String>) document.get("genres"));

            if (document.containsKey("tomatoes")) {
                movie.setTomatoes(mapToRottenTomatoes((Document) document.get("tomatoes")));
            }

            movie.setPoster(document.getString("poster"));

            if (document.containsKey("schedules")) {
                List<FilmSchedule> filmSchedules = new ArrayList<>();

                for (Document filmSchedule : (List<Document>) document.get("schedules")) {
                    System.out.println(filmSchedule);
                    filmSchedules.add(parseFilmSchedule(filmSchedule));
                }
                movie.setFilmSchedules(filmSchedules);
            }

        } catch (Exception e) {
            log.warn("Unable to map document `{}` to `Movie` object: {} ", document, e.getMessage());
            log.warn("Skipping document");
        }
        return movie;
    }

    public static List<MovieSchedule> mapToMovieScheduleSingleSchedule(List<Document> documents) {

        List<MovieSchedule> movieSchedules = new ArrayList<>();

        for (Document document : (documents)) {

            MovieSchedule movie = new MovieSchedule();
            try {
                movie.setId(document.getObjectId("_id").toHexString());
                movie.setTitle(MessageFormat.format("{0}", document.get("title")));
                movie.setCast((List<String>) document.get("cast"));
                movie.setPlog(document.getString("plot"));
                movie.setFullPlot(document.getString("fullplot"));

                movie.setLastUpdated(parseDate(document.get("lastupdated")));

                movie.setType(document.getString("type"));
                movie.setDirectors((List<String>) document.get("directors"));
                movie.setWriters((List<String>) document.get("writers"));

                if (document.containsKey("imdb")) {
                    movie.setImdb(mapToIMDB((Document) document.get("imdb")));
                }

                movie.setCountries((List<String>) document.get("countries"));
                movie.setGenres((List<String>) document.get("genres"));

                if (document.containsKey("tomatoes")) {
                    movie.setTomatoes(mapToRottenTomatoes((Document) document.get("tomatoes")));
                }

                movie.setPoster(document.getString("poster"));


                Document scheduleDoc = (Document) document.get("schedules");

                FilmSchedule filmSchedule = new FilmSchedule();
                filmSchedule.setDate(scheduleDoc.getDate("date"));
                filmSchedule.setId(scheduleDoc.getObjectId("_id").toHexString());
                filmSchedule.setMovieId(scheduleDoc.getObjectId("movie_id").toHexString());
                LinkedHashSet<String> strings = new LinkedHashSet<>();
                strings.addAll((List<String>) scheduleDoc.get("time"));
                filmSchedule.setTime(strings);

                movie.setFilmSchedule(filmSchedule);
//                movie.setFilmSchedule(parseFilmSchedule(scheduleDoc));

                movieSchedules.add(movie);

            } catch (Exception e) {
                log.warn("Unable to map document `{}` to `Movie` object: {} ", document, e.getMessage());
                log.warn("Skipping document");
            }
        }

        return movieSchedules;
    }

    private static FilmSchedule parseFilmSchedule(Document document) {
        FilmSchedule filmSchedule = new FilmSchedule();
        filmSchedule.setDate(document.getDate("date"));
        filmSchedule.setId(document.getObjectId("_id").toHexString());
        filmSchedule.setMovieId(document.getObjectId("movie_id").toHexString());
        LinkedHashSet<String> strings = new LinkedHashSet<>();
        strings.addAll((List<String>) document.get("time"));
        filmSchedule.setTime(strings);

        return filmSchedule;
    }

    private static Comment parseComment(Document document) {
        Comment comment = new Comment();
        comment.setId(document.getObjectId("_id").toHexString());
        comment.setText(document.getString("text"));
        comment.setEmail(document.getString("email"));
        comment.setDate(document.getDate("date"));
        comment.setMovieId(document.getObjectId("movie_id").toHexString());
        comment.setName(document.getString("name"));
        return comment;
    }

    public static Date parseDate(Object stringDate) {
        if (stringDate == null) {
            return null;
        }
        try {
            if (stringDate instanceof String) {
                return sdf.parse((String) stringDate);
            }
            if (stringDate instanceof Date) {
                return (Date) stringDate;
            }
        } catch (ParseException ex) {
            log.error("Error parsing `{}` string into Date object: {}", stringDate, ex.getMessage());
        }
        return null;
    }

    private static RottenTomatoes mapToRottenTomatoes(Document document) {
        RottenTomatoes tomatoes = new RottenTomatoes();
        if (document == null) {
            return tomatoes;
        }
        tomatoes.setLastUpdated(parseDate(document.getString("lastupdated")));
        if (document.containsKey("viewer")) {
            tomatoes.setViewer(mapToViewerRating((Document) document.get("viewer")));
        }

        return tomatoes;
    }

    private static ViewerRating mapToViewerRating(Document document) {
        ViewerRating viewer = new ViewerRating();
        if (document == null) {
            return viewer;
        }
        viewer.setNumReviews(document.getInteger("numReviews"));
        viewer.setRating(document.getDouble("rating"));

        return viewer;
    }

    private static IMDB mapToIMDB(Document document) {
        IMDB imdb = new IMDB();
        if (document == null) {
            return imdb;
        }
        imdb.setId(document.getInteger("id"));

        imdb.setRating(parseDouble(document.get("rating")));
        imdb.setVotes(parseInt(document.get("votes")));
        return imdb;
    }

    public static Integer parseInt(Object o) {
        if (o instanceof String) {
            if ("".equals(o)) {
                return 0;
            }
            return Integer.valueOf((String) o);
        }
        return ((Number) o).intValue();
    }

    private static Double parseDouble(Object rating) {
        if (rating instanceof String) {
            if ("".equals(rating)) {
                return (double) 0;
            }
            return Double.parseDouble((String) rating);
        }
        return ((Number) rating).doubleValue();
    }
}
