package mflix.api.controllers;

import mflix.api.models.FilmScheduleDTO;
import mflix.api.models.MovieSchedule;
import mflix.api.services.ScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping(path = "/api/v1/schedule")
public class ScheduleController {

    @Autowired
    private ScheduleService scheduleService;

    public ScheduleController() {
        super();
    }

    @PostMapping("/addschedule")
    public ResponseEntity addFilmSchedule(@RequestBody FilmScheduleDTO filmSchedule) {
        //    System.out.println(filmSchedule);
        if (scheduleService.addMovieSchedule(
                filmSchedule.getMovieId(), filmSchedule.getDate(), filmSchedule.getTime())) {
            return ResponseEntity.ok(filmSchedule);
        }

        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/getschedulewithidmovie")
    public ResponseEntity getFilmSchedule(
            @RequestParam(value = "date", required = true) @DateTimeFormat(pattern = "yyyy-MM-dd") Date date,
            @RequestParam(value = "movieId", required = false) String movieId,
            @RequestParam(value = "startTime", required = false) String startTime,
            @RequestParam(value = "endTime", required = false) String endTime) {
        Map<String, Object> results = new HashMap<>();
        if (movieId == null && startTime != null && endTime != null && date != null) {
            List<MovieSchedule> movieSchedules = scheduleService.getMovieScheduleByDateAndTimerange(date, startTime, endTime);
            results.put("movies", movieSchedules);
            return ResponseEntity.ok(results);
        } else if (startTime == null && endTime == null) {
            MovieSchedule movieSchedule =
                    scheduleService.getMovieScheduleAfterDate(movieId, date);
            return ResponseEntity.ok(movieSchedule);
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/getschedulewithdate")
    public ResponseEntity getFilmSchedulewithdate(
            @RequestParam(value = "date", required = true) @DateTimeFormat(pattern = "yyyy-MM-dd") Date date) {
        Map<String, Object> results = new HashMap<>();
        if (date != null) {
            List<MovieSchedule> movieSchedules = scheduleService.getMovieScheduleByDate(date);
            results.put("movies", movieSchedules);
            return ResponseEntity.ok(results);
        }
        return ResponseEntity.badRequest().build();
    }


    @GetMapping("/updateschedulewithmovieidanddateandtime")
    public ResponseEntity updateFilmSchedulewithdate(
            @RequestParam(value = "date", required = true) @DateTimeFormat(pattern = "yyyy-MM-dd") Date date,
            @RequestParam(value = "movieId", required = false) String movieId,
            @RequestParam(value = "time", required = false) String time,
            @RequestParam(value = "newtime", required = true) String newtime){
        Map<String, Object> results = new HashMap<>();
        if (date != null) {
            boolean res=   scheduleService.updateSchedule(movieId, date, time, newtime);
            results.put("tb", res);
            return ResponseEntity.ok(results);
        }
        return ResponseEntity.badRequest().build();
    }
}
