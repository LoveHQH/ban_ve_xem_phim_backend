package mflix.api.controllers;

import mflix.api.models.BookingDTO;
import mflix.api.services.BookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.BinaryOperator;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping(path = "/api/v1/booking")
public class BookingController extends ApiController {
    //  public class BookingController  {
    @Autowired
    private BookingService bookingService;

    public BookingController() {
        super();
    }

    @Override
    ResponseEntity<Map> index() {
        return ResponseEntity.ok(Collections.emptyMap());
    }

    @GetMapping(value = "/booking")
    public ResponseEntity getBookings(
            @RequestParam(value = "id") String id,
            @RequestParam(value = "showing") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
                    Date bookedDated) {
        System.out.println(id);
        System.out.println(bookedDated);
        List<BookingDTO> bookingDTOS = bookingService.getBookings(id, bookedDated);

        return ResponseEntity.ok().body(bookingDTOS);
    }

    @PostMapping("/booking")
    public ResponseEntity addBooking(@RequestBody BookingDTO bookingDTO) {
        System.out.println(bookingDTO);
        bookingDTO = bookingService.addBooking(bookingDTO);

        return ResponseEntity.ok(bookingDTO);
    }

    @GetMapping(value = "/bookingafterdate")
    public ResponseEntity getBookings()
//          @RequestParam(value = "showing") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
//                  Date bookedDated)
    {
//        System.out.println(bookedDated);
        List<BookingDTO> bookingDTOS = bookingService.getall();

        return ResponseEntity.ok().body(bookingDTOS);
    }
}
