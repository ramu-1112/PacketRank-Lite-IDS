import folium

class Map:
    def __init__(self):
        self.map = folium.Map(location=[20,0],zoom_start=2,tiles="https://mt1.google.com/vt/lyrs=m&x={x}&y={y}&z={z}",attr="Google",zoom_control=False,)

    def get_html(self):
        return self.map._repr_html_()
    
map_trace = Map()