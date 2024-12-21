<template>
  <div class="product-detail">
    <el-row :gutter="40">
      <!-- Product Image -->
      <el-col :span="12">
        <div class="product-image">
          <img :src="product.imageUrl || 'https://via.placeholder.com/400'" alt="Product Image">
        </div>
      </el-col>

      <!-- Product Info -->
      <el-col :span="12">
        <div class="product-info">
          <h1>{{ product.name }}</h1>
          <div class="price">$ {{ product.price }}</div>
          
          <div class="stock-info" :class="{ 'low-stock': product.stock < 10 }">
            {{ product.stock }} in stock
          </div>

          <div class="description">
            <h3>Description</h3>
            <p>{{ product.description }}</p>
          </div>

          <div class="brand-category">
            <p><strong>Brand:</strong> {{ product.brand }}</p>
            <p><strong>Category:</strong> {{ product.category }}</p>
          </div>

          <div class="quantity-selector">
            <el-input-number 
              v-model="quantity" 
              :min="1" 
              :max="product.stock"
              :disabled="product.stock === 0">
            </el-input-number>
          </div>

          <div class="actions">
            <el-button 
              type="primary" 
              size="large"
              :disabled="product.stock === 0"
              @click="addToCart">
              Add to Cart
            </el-button>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- Reviews Section -->
    <div class="reviews-section">
      <h2>Customer Reviews</h2>
      <div class="review-stats">
        <div class="average-rating">
          <h3>{{ product.averageRating?.toFixed(1) || 'No' }} / 5</h3>
          <el-rate 
            v-model="product.averageRating" 
            disabled 
            show-score>
          </el-rate>
          <p>{{ product.reviewCount || 0 }} reviews</p>
        </div>
      </div>

      <div class="add-review" v-if="isLoggedIn">
        <h3>Write a Review</h3>
        <el-form :model="reviewForm" @submit.prevent="submitReview">
          <el-form-item>
            <el-rate v-model="reviewForm.rating"></el-rate>
          </el-form-item>
          <el-form-item>
            <el-input
              v-model="reviewForm.comment"
              type="textarea"
              rows="4"
              placeholder="Share your thoughts about this product...">
            </el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="submitReview">Submit Review</el-button>
          </el-form-item>
        </el-form>
      </div>

      <div class="reviews-list">
        <el-empty v-if="reviews.length === 0" description="No reviews yet"></el-empty>
        <el-card v-for="review in reviews" :key="review.id" class="review-item">
          <div class="review-header">
            <span class="reviewer">{{ review.user.username }}</span>
            <el-rate v-model="review.rating" disabled></el-rate>
            <span class="review-date">{{ formatDate(review.reviewDate) }}</span>
          </div>
          <div class="review-content">
            {{ review.comment }}
          </div>
        </el-card>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useUserStore } from '../stores/user'
import { ElMessage } from 'element-plus'
import axios from 'axios'

const route = useRoute()
const router = useRouter()
const userStore = useUserStore()

const product = ref({})
const reviews = ref([])
const quantity = ref(1)
const isLoggedIn = computed(() => userStore.isLoggedIn)

const reviewForm = ref({
  rating: 0,
  comment: ''
})

const loadProduct = async () => {
  try {
    const response = await axios.get(`/api/products/${route.params.id}`)
    product.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load product')
  }
}

const loadReviews = async () => {
  try {
    const response = await axios.get(`/api/reviews/products/${route.params.id}`)
    reviews.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load reviews')
  }
}

const addToCart = async () => {
  if (!isLoggedIn.value) {
    router.push('/login')
    return
  }

  try {
    await axios.post('/api/cart/add', {
      productId: product.value.id,
      quantity: quantity.value
    })
    ElMessage.success('Added to cart')
  } catch (error) {
    ElMessage.error(error.response?.data?.error || 'Failed to add to cart')
  }
}

const submitReview = async () => {
  try {
    await axios.post(`/api/reviews/products/${route.params.id}`, reviewForm.value)
    ElMessage.success('Review submitted')
    reviewForm.value = { rating: 0, comment: '' }
    await loadReviews()
  } catch (error) {
    ElMessage.error(error.response?.data?.error || 'Failed to submit review')
  }
}

const formatDate = (date) => {
  return new Date(date).toLocaleDateString()
}

onMounted(() => {
  loadProduct()
  loadReviews()
})
</script>

<style scoped>
.product-detail {
  max-width: 1200px;
  margin: 0 auto;
  padding: 40px 20px;
}

.product-image img {
  width: 100%;
  height: auto;
  border-radius: 8px;
  box-shadow: 0 2px 12px 0 rgba(0,0,0,0.1);
}

.product-info {
  padding: 20px;
}

.product-info h1 {
  margin-bottom: 20px;
  color: #2c3e50;
}

.price {
  font-size: 2em;
  color: #409EFF;
  margin: 20px 0;
}

.stock-info {
  color: #67C23A;
  margin: 10px 0;
}

.low-stock {
  color: #E6A23C;
}

.description {
  margin: 20px 0;
}

.brand-category {
  margin: 20px 0;
  color: #606266;
}

.quantity-selector {
  margin: 20px 0;
}

.actions {
  margin-top: 30px;
}

.reviews-section {
  margin-top: 60px;
}

.review-stats {
  text-align: center;
  margin: 30px 0;
}

.average-rating h3 {
  font-size: 2em;
  margin: 10px 0;
}

.add-review {
  max-width: 600px;
  margin: 40px auto;
}

.reviews-list {
  margin-top: 40px;
}

.review-item {
  margin-bottom: 20px;
}

.review-header {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-bottom: 10px;
}

.reviewer {
  font-weight: bold;
}

.review-date {
  color: #909399;
}

.review-content {
  color: #606266;
  line-height: 1.6;
}
</style> 