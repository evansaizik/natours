const express = require('express');

const router = express.Router();
const {
  // checkID,
  aliasTopTours,
  getAllTours,
  createTour,
  getTour,
  updateTour,
  deleteTour,
  getTourStats,
  getMonthlyPlan,
} = require(`../controllers/tourController`);
const { protect, restrictTo } = require('../controllers/authController');

const reviewRouter = require('./reviewRoutes');

// POST /tour/2103410ibk3/reviews
// GET /tour/2103410ibk3/reviews

router.use('/:tourId/reviews', reviewRouter);

// router.param('id', checkID);
router.route('/top-5-cheap').get(aliasTopTours, getAllTours);

router.route('/tour-stats').get(getTourStats);
router.route('/monthly-plan/:year').get(getMonthlyPlan);

router.route('/').get(protect, getAllTours).post(createTour);

router
  .route('/:id')
  .get(getTour)
  .patch(updateTour)
  .delete(protect, restrictTo('admin', 'lead-guide'), deleteTour);

module.exports = router;
