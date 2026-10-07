from flask import Flask, render_template
from pages import pages_bp

app = Flask(__name__)
app.register_blueprint(pages_bp)

@app.route("/crypto-test")
def crypto_test():
    return render_template("crypto_test.html")


if __name__ == "__main__":
    app.run(debug=True)