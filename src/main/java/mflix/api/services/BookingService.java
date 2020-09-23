package mflix.api.services;

import mflix.api.daos.BookingDao;
import mflix.api.models.BookingDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
@Configuration
public class BookingService {
    @Autowired private BookingDao bookingDao;

    public BookingService() {super();}

    public BookingDTO addBooking(BookingDTO bookingDTO) {
        bookingDao.addBooking(bookingDTO);
        return bookingDTO;
    }

    public List<BookingDTO> getBookings(String movieId, Date showing) {
        return bookingDao.getBooking(movieId,showing);
    }


    public List<BookingDTO> getall() {
        return bookingDao.getall();
    }
}
