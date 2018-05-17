# SAMPLE R FUNCTION

hasIPformat <- function(ip) {
  b <- as.logical(length(grep("^\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}$", x = ip)))
  if (b == TRUE) {
    k <- unlist(strsplit(ip,".", fixed = TRUE))
    b <- all(sapply(k, function(x) as.integer(x) < 256) == TRUE)
  }
  return(as.logical(b))
}
