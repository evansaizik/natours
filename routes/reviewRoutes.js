const express = require('express');
const { protect, restrictTo } = require('../controllers/authController');
const {
  getAllReviews,
  createReview,
  deleteReview,
} = require('../controllers/reviewController');

const router = express.Router({ mergeParams: true });

router
  .route('/')
  .get(protect, restrictTo('user'), getAllReviews)
  .post(protect, restrictTo('user'), createReview);

router
  .route('/:id')
  .delete(protect, restrictTo('admin', 'lead-guide'), deleteReview);

module.exports = router;
