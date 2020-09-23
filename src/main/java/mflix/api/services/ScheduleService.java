package mflix.api.services;

import mflix.api.daos.MovieDao;
import mflix.api.daos.ScheduleDao;
import mflix.api.models.FilmSchedule;
import mflix.api.models.Movie;
import mflix.api.models.MovieSchedule;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Service;

import java.sql.Array;
import java.sql.Time;
import java.util.*;

import static mflix.api.daos.MovieDocumentMapper.mapToMovieSchedule;
import static mflix.api.daos.MovieDocumentMapper.mapToMovieScheduleSingleSchedule;

@Service
@Configuration
public class ScheduleService {

    @Autowired
    private ScheduleDao scheduleDao;
    @Autowired
    private MovieDao movieDao;

    public ScheduleService() {
        super();
    }

    public boolean addMovieSchedule(String movieId, Date date, LinkedHashSet<String> timeList) {
        FilmSchedule filmSchedule = scheduleDao.getScheduleByMovieIdAndDate(movieId, date);

        if (filmSchedule == null) {
            filmSchedule = new FilmSchedule();
            filmSchedule.setOid(new ObjectId());
            filmSchedule.setMovieId(movieId);
            filmSchedule.setDate(date);
            filmSchedule.setTime(timeList);
            scheduleDao.addSchedule(filmSchedule);
        } else {
            filmSchedule.getTime().addAll(timeList);
            scheduleDao.updateSchedule(filmSchedule);
        }
        return true;
    }

    public MovieSchedule getMovieScheduleAfterDate(String movieId, Date date) {
    /* TODO pass only date to get list of schedule,
        then compare first date 's hour:minute with time array 's element
     *   */
        Document document = movieDao.getMovieAndScheduleAfterDate(movieId, date);
        MovieSchedule movieSchedule = mapToMovieSchedule(document);

        return movieSchedule;
    }


    public List<MovieSchedule> getMovieScheduleByDateAndTimerange(Date date, String startTime, String endTime) {

        List<Document> documents = movieDao.getMovieAndScheduleByDate(date);
        List<MovieSchedule> movieSchedules = mapToMovieScheduleSingleSchedule(documents);
        for (Iterator<MovieSchedule> movieScheduleIterator = movieSchedules.iterator(); movieScheduleIterator.hasNext(); ) {
            MovieSchedule movieSchedule = movieScheduleIterator.next();
            Iterator<String> iter = movieSchedule.getFilmSchedule().getTime().iterator();
            while (iter.hasNext()) {
                String str = iter.next();
                int cmpS = str.compareTo(startTime);
                int cmpE = str.compareTo(endTime);
                if (cmpS < 0 || cmpE > 0) {
                    iter.remove();
                }
            }
            if (movieSchedule.getFilmSchedule().getTime().size() == 0) {
                movieScheduleIterator.remove();
            }
        }

        return movieSchedules;
    }


    public List<MovieSchedule> getMovieScheduleByDate(Date date) {

        List<Document> documents = movieDao.getMovieAndScheduleByDate(date);
        List<MovieSchedule> movieSchedules = mapToMovieScheduleSingleSchedule(documents);

        return movieSchedules;
    }

    public boolean updateSchedule(String movieId, Date date, String time, String newtime) {

        FilmSchedule filmSchedulebase = scheduleDao.getScheduleByMovieIdAndDate(movieId, date);

        FilmSchedule filmSchedule = new FilmSchedule();
        filmSchedule.setMovieId(movieId);
        filmSchedule.setDate(date);
        LinkedHashSet<String> listtime = new LinkedHashSet<>();
        for (Iterator<String> s = filmSchedulebase.getTime().iterator(); s.hasNext(); ) {
            String currTime = s.next();
            if (currTime.equals(time)) continue;
            listtime.add(currTime);
        }
        listtime.add(newtime);
        filmSchedule.setTime(listtime);

        boolean res = scheduleDao.updateSchedule(filmSchedule);
        return res;
    }

}
