<template>
  <div class="product-list">
    <div class="filters">
      <el-row :gutter="20" class="filter-row">
        <el-col :span="8">
          <el-input
              v-model="searchQuery"
              placeholder="Search products..."
              prefix-icon="Search"
              clearable
              @input="handleSearch"
          />
        </el-col>
        <el-col :span="6">
          <el-select v-model="selectedCategory" placeholder="Category" clearable @change="handleFilter">
            <el-option label="Electronics" value="electronics" />
            <el-option label="Clothing" value="clothing" />
            <el-option label="Books" value="books" />
            <el-option label="Home" value="home" />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-select v-model="sortBy" placeholder="Sort by" @change="handleSort">
            <el-option label="Price: Low to High" value="price_asc" />
            <el-option label="Price: High to Low" value="price_desc" />
            <el-option label="Name: A to Z" value="name_asc" />
            <el-option label="Name: Z to A" value="name_desc" />
          </el-select>
        </el-col>
      </el-row>
    </div>

    <el-row :gutter="20" class="products">
      <el-col :span="6" v-for="product in products" :key="product.id">
        <el-card shadow="hover" class="product-card">
          <img :src="product.imageUrl || 'https://via.placeholder.com/200'" class="product-image" />
          <div class="product-info">
            <h3>{{ product.name }}</h3>
            <div class="price">$ {{ product.price }}</div>
            <div class="stock" :class="{ 'low-stock': product.stock < 10 }">
              {{ product.stock }} in stock
            </div>
            <div class="actions">
              <el-button type="primary" @click="viewDetails(product.id)">View Details</el-button>
              <el-button
                  type="success"
                  :disabled="product.stock === 0"
                  @click="addToCart(product)">
                Add to Cart
              </el-button>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <div v-if="loading" class="loading">
      <el-loading :fullscreen="true" />
    </div>

    <div v-if="!loading && products.length === 0" class="no-results">
      <el-empty description="No products found" />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import axios from 'axios'

const router = useRouter()
const products = ref([])
const loading = ref(false)
const searchQuery = ref('')
const selectedCategory = ref('')
const sortBy = ref('')

const loadProducts = async () => {
  try {
    loading.value = true
    const response = await axios.get('/api/products')
    products.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load products')
  } finally {
    loading.value = false
  }
}

const handleSearch = async () => {
  if (searchQuery.value) {
    try {
      loading.value = true
      const response = await axios.get(`/api/products/search?keyword=${searchQuery.value}`)
      products.value = response.data
    } catch (error) {
      ElMessage.error('Search failed')
    } finally {
      loading.value = false
    }
  } else {
    loadProducts()
  }
}

const handleFilter = async () => {
  if (selectedCategory.value) {
    try {
      loading.value = true
      const response = await axios.get(`/api/products/category/${selectedCategory.value}`)
      products.value = response.data
    } catch (error) {
      ElMessage.error('Failed to filter products')
    } finally {
      loading.value = false
    }
  } else {
    loadProducts()
  }
}

const handleSort = async () => {
  if (!sortBy.value) return

  const [field, direction] = sortBy.value.split('_')
  try {
    loading.value = true
    const response = await axios.get(`/api/products/sort?sortBy=${field}&ascending=${direction === 'asc'}`)
    products.value = response.data
  } catch (error) {
    ElMessage.error('Failed to sort products')
  } finally {
    loading.value = false
  }
}

const viewDetails = (productId) => {
  router.push(`/products/${productId}`)
}

const addToCart = async (product) => {
  try {
    await axios.post('/api/cart/add', {
      productId: product.id,
      quantity: 1
    })
    ElMessage.success('Added to cart')
  } catch (error) {
    if (error.response?.status === 401) {
      router.push('/login')
    } else {
      ElMessage.error(error.response?.data?.error || 'Failed to add to cart')
    }
  }
}

onMounted(() => {
  loadProducts()
})
</script>

<style scoped>
.product-list {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.filters {
  margin-bottom: 30px;
}

.filter-row {
  display: flex;
  align-items: center;
}

.products {
  margin-top: 20px;
}

.product-card {
  margin-bottom: 20px;
  transition: transform 0.3s;
}

.product-card:hover {
  transform: translateY(-5px);
}

.product-image {
  width: 100%;
  height: 200px;
  object-fit: cover;
}

.product-info {
  padding: 15px;
  text-align: center;
}

.product-info h3 {
  margin: 10px 0;
  font-size: 1.2em;
}

.price {
  color: #409EFF;
  font-size: 1.2em;
  margin: 10px 0;
  font-weight: bold;
}

.stock {
  margin: 10px 0;
  color: #67C23A;
}

.low-stock {
  color: #E6A23C;
}

.actions {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 15px;
}

.no-results {
  margin-top: 40px;
  text-align: center;
}
</style>