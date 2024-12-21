<template>
  <div id="app">
    <Header />
    <main class="main-content">
      <router-view></router-view>
    </main>
  </div>
</template>

<script setup>
import Header from './components/Header.vue'
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
  min-height: 100vh;
}

body {
  margin: 0;
  padding: 0;
}

.main-content {
  padding-top: 60px; /* 为固定的 header 留出空间 */
  min-height: calc(100vh - 60px);
}
</style>