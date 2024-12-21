<template>
  <div class="home">
    <el-row :gutter="20" class="welcome-section">
      <el-col :span="24">
        <h1>Welcome to E-Shop</h1>
        <p>Discover the Latest Products and Deals</p>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="featured-products">
      <el-col :span="24">
        <h2>Featured Products</h2>
      </el-col>
      <el-col :span="6" v-for="i in 4" :key="i">
        <el-card shadow="hover" class="product-card">
          <img src="https://via.placeholder.com/200" class="product-image" />
          <div class="product-info">
            <h3>Sample Product {{ i }}</h3>
            <p>$ 199.00</p>
            <el-button type="primary">查看详情</el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.home {
  padding: 20px;
}

.welcome-section {
  text-align: center;
  margin-bottom: 40px;
}

.welcome-section h1 {
  font-size: 2.5em;
  color: #409EFF;
}

.featured-products {
  margin-top: 20px;
}

.featured-products h2 {
  margin-bottom: 20px;
}

.product-card {
  margin-bottom: 20px;
}

.product-image {
  width: 100%;
  height: 200px;
  object-fit: cover;
}

.product-info {
  padding: 10px;
  text-align: center;
}

.product-info h3 {
  margin: 10px 0;
}

.product-info p {
  color: #409EFF;
  font-size: 1.2em;
  margin: 10px 0;
}
</style>